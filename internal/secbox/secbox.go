// Package secbox implements the passphrase-encrypted secrets container (.mimosec),
// password policy validation, and secret-value redaction for plaintext copies.
package secbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Container layout (all integers big-endian):
//
//	off  len  field
//	0    8    magic "MIMOSEC1"
//	8    2    version u16 = 2 (v1 reserved)
//	10   2    kdf_id u16 = 2 (argon2id)
//	12   4    m_cost u32 (KiB)
//	16   4    t_cost u32
//	20   4    p_cost u32
//	24   4    salt_len u32 = 32
//	28   32   salt
//	60   12   nonce
//	72   …    ct||tag = AES-256-GCM(key, nonce, payload), AAD = header[0:72]
const (
	magicLen   = 8
	headerLen  = 72
	saltLen    = 32
	nonceLen   = 12
	keyLen     = 32
	versionArg = 2
	kdfArgon2  = 2

	// Default KDF cost parameters (OWASP: m>=19MiB, t>=2, p>=1).
	DefaultMCost = 64 * 1024 // 64 MiB in KiB
	DefaultTCost = 3
	DefaultPCost = 1

	// Open-side upper bounds to defeat cost-parameter bombs in untrusted containers.
	maxMCost = 1024 * 1024 // 1 GiB in KiB
	maxTCost = 16
	maxPCost = 16

	// MaxPayload is the largest secrets payload accepted for in-memory AEAD.
	MaxPayload = 512 << 20 // 512 MiB
)

var (
	magic = [magicLen]byte{'M', 'I', 'M', 'O', 'S', 'E', 'C', '1'}

	// ErrAuth reports a failed AEAD authentication (wrong passphrase or corruption).
	ErrAuth = errors.New("wrong passphrase or corrupted secrets container")
	// ErrFormat reports a structurally invalid container.
	ErrFormat = errors.New("invalid secrets container")
)

// Params holds Argon2id cost parameters.
type Params struct {
	M uint32 // memory KiB
	T uint32 // iterations
	P uint32 // parallelism
}

// DefaultParams returns the standard cost parameters.
func DefaultParams() Params {
	return Params{M: DefaultMCost, T: DefaultTCost, P: DefaultPCost}
}

func (p Params) validateForOpen() error {
	if p.M == 0 || p.M > maxMCost {
		return fmt.Errorf("%w: m_cost %d out of range", ErrFormat, p.M)
	}
	if p.T == 0 || p.T > maxTCost {
		return fmt.Errorf("%w: t_cost %d out of range", ErrFormat, p.T)
	}
	if p.P == 0 || p.P > maxPCost {
		return fmt.Errorf("%w: p_cost %d out of range", ErrFormat, p.P)
	}
	return nil
}

// Seal encrypts payload with a key derived from passphrase and writes the container to w.
func Seal(passphrase, payload []byte, p Params, w io.Writer) (int, error) {
	if len(payload) > MaxPayload {
		return 0, fmt.Errorf("%w: payload %d exceeds limit %d", ErrFormat, len(payload), MaxPayload)
	}
	if err := p.validateForOpen(); err != nil {
		return 0, err
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return 0, fmt.Errorf("read salt: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return 0, fmt.Errorf("read nonce: %w", err)
	}

	header := make([]byte, headerLen)
	copy(header[0:8], magic[:])
	binary.BigEndian.PutUint16(header[8:10], versionArg)
	binary.BigEndian.PutUint16(header[10:12], kdfArgon2)
	binary.BigEndian.PutUint32(header[12:16], p.M)
	binary.BigEndian.PutUint32(header[16:20], p.T)
	binary.BigEndian.PutUint32(header[20:24], p.P)
	binary.BigEndian.PutUint32(header[24:28], saltLen)
	copy(header[28:60], salt)
	copy(header[60:72], nonce)

	key := derive(passphrase, salt, p)
	defer zero(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, fmt.Errorf("aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return 0, fmt.Errorf("gcm: %w", err)
	}
	ct := aead.Seal(nil, nonce, payload, header)

	n, err := w.Write(header)
	if err != nil {
		return n, fmt.Errorf("write header: %w", err)
	}
	m, err := w.Write(ct)
	return n + m, err
}

// Open authenticates and decrypts a container produced by Seal.
func Open(passphrase, container []byte) ([]byte, error) {
	if len(container) < headerLen+16 {
		return nil, fmt.Errorf("%w: truncated", ErrFormat)
	}
	h := container[:headerLen]
	if string(h[0:8]) != string(magic[:]) {
		return nil, fmt.Errorf("%w: bad magic", ErrFormat)
	}
	if v := binary.BigEndian.Uint16(h[8:10]); v != versionArg {
		return nil, fmt.Errorf("%w: unsupported version %d (v1 reserved)", ErrFormat, v)
	}
	if k := binary.BigEndian.Uint16(h[10:12]); k != kdfArgon2 {
		return nil, fmt.Errorf("%w: unsupported kdf_id %d", ErrFormat, k)
	}
	p := Params{
		M: binary.BigEndian.Uint32(h[12:16]),
		T: binary.BigEndian.Uint32(h[16:20]),
		P: binary.BigEndian.Uint32(h[20:24]),
	}
	if err := p.validateForOpen(); err != nil {
		return nil, err
	}
	if sl := binary.BigEndian.Uint32(h[24:28]); sl != saltLen {
		return nil, fmt.Errorf("%w: salt_len %d", ErrFormat, sl)
	}
	salt := h[28:60]
	nonce := h[60:72]

	key := derive(passphrase, salt, p)
	defer zero(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	payload, err := aead.Open(nil, nonce, container[headerLen:], h)
	if err != nil {
		return nil, ErrAuth
	}
	return payload, nil
}

// ParamsOf reports the KDF parameters stored in a container header.
// It performs no decryption; bounds are validated.
func ParamsOf(container []byte) (Params, error) {
	if len(container) < headerLen {
		return Params{}, fmt.Errorf("%w: truncated", ErrFormat)
	}
	h := container[:headerLen]
	if string(h[0:8]) != string(magic[:]) {
		return Params{}, fmt.Errorf("%w: bad magic", ErrFormat)
	}
	p := Params{
		M: binary.BigEndian.Uint32(h[12:16]),
		T: binary.BigEndian.Uint32(h[16:20]),
		P: binary.BigEndian.Uint32(h[20:24]),
	}
	if err := p.validateForOpen(); err != nil {
		return Params{}, err
	}
	return p, nil
}

func derive(passphrase, salt []byte, p Params) []byte {
	pw := passphrase
	if len(pw) > 1024 {
		sum := sha256.Sum256(pw)
		pw = sum[:]
	}
	return argon2.IDKey(pw, salt, p.T, p.M, uint8(p.P), keyLen)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
