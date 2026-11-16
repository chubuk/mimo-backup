package secbox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

// Streaming container layout (all integers big-endian), magic "MIMOSEC2":
//
//	off  len  field
//	0    8    magic "MIMOSEC2"
//	8    2    version u16 = 1
//	10   2    kdf_id u16 = 2 (argon2id)
//	12   4    m_cost u32 (KiB)
//	16   4    t_cost u32
//	20   4    p_cost u32
//	24   4    salt_len u32 = 32
//	28   32   salt
//	60   12   base_nonce
//	72   …    chunks: repeated [u32 ct_len][ct]
//	           ct = AES-256-GCM(key, nonce_i) over ≤ChunkSize plaintext
//	           nonce_i = base_nonce with last 8 bytes XOR counter i
//	           AAD = header[0:72] || u64be(i)
//	           a final chunk with empty plaintext (ct_len = 16) ends the stream
//
// Unlike the in-memory v2 container (magic MIMOSEC1), this format streams
// O(1) memory and therefore wraps whole archives.
const (
	streamVersion = 1
	// ChunkSize is the plaintext unit of one AEAD seal.
	ChunkSize = 64 << 10
)

var streamMagic = [magicLen]byte{'M', 'I', 'M', 'O', 'S', 'E', 'C', '2'}

// LooksEncrypted reports whether raw starts with either container magic.
// It is the authoritative encryption test — file suffixes are not.
func LooksEncrypted(raw []byte) bool {
	return bytes.HasPrefix(raw, magic[:]) || bytes.HasPrefix(raw, streamMagic[:])
}

// SealStream encrypts r into w using the chunked container format.
// Returns the number of plaintext bytes consumed.
func SealStream(w io.Writer, r io.Reader, passphrase []byte, p Params) (int64, error) {
	s, err := NewSealer(w, passphrase, p)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(s, r)
	if err != nil {
		return n, err
	}
	return n, s.Close()
}

// Sealer is a push-style chunked encryptor: Write buffers plaintext and
// seals full chunks; Close flushes the tail and writes the terminator.
type Sealer struct {
	w       io.Writer
	aead    cipher.AEAD
	header  []byte
	base    []byte
	buf     []byte
	filled  int
	counter uint64
	total   int64
	closed  bool
}

// NewSealer starts a chunked container on w.
func NewSealer(w io.Writer, passphrase []byte, p Params) (*Sealer, error) {
	if err := p.validateForOpen(); err != nil {
		return nil, err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("read salt: %w", err)
	}
	baseNonce := make([]byte, nonceLen)
	if _, err := rand.Read(baseNonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	header := make([]byte, headerLen)
	copy(header[0:8], streamMagic[:])
	binary.BigEndian.PutUint16(header[8:10], streamVersion)
	binary.BigEndian.PutUint16(header[10:12], kdfArgon2)
	binary.BigEndian.PutUint32(header[12:16], p.M)
	binary.BigEndian.PutUint32(header[16:20], p.T)
	binary.BigEndian.PutUint32(header[20:24], p.P)
	binary.BigEndian.PutUint32(header[24:28], saltLen)
	copy(header[28:60], salt)
	copy(header[60:72], baseNonce)

	key := derive(passphrase, salt, p)
	aead, err := newAEAD(key)
	zero(key) // the cipher keeps its own copy
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(header); err != nil {
		zero(key)
		return nil, fmt.Errorf("write header: %w", err)
	}
	return &Sealer{
		w:      w,
		aead:   aead,
		header: header,
		base:   baseNonce,
		buf:    make([]byte, ChunkSize),
	}, nil
}

// Write buffers plaintext and seals full chunks.
func (s *Sealer) Write(p []byte) (int, error) {
	if s.closed {
		return 0, fmt.Errorf("sealer closed")
	}
	written := 0
	for len(p) > 0 {
		n := copy(s.buf[s.filled:], p)
		s.filled += n
		p = p[n:]
		written += n
		s.total += int64(n)
		if s.filled == ChunkSize {
			if err := s.sealChunk(s.buf[:s.filled]); err != nil {
				return written, err
			}
			s.filled = 0
		}
	}
	return written, nil
}

// Close flushes the tail chunk and writes the terminator.
func (s *Sealer) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if s.filled > 0 {
		if err := s.sealChunk(s.buf[:s.filled]); err != nil {
			return err
		}
		s.filled = 0
	}
	ct := s.aead.Seal(nil, chunkNonce(s.base, s.counter), nil, chunkAAD(s.header, s.counter))
	return writeChunk(s.w, ct)
}

func (s *Sealer) sealChunk(plain []byte) error {
	ct := s.aead.Seal(nil, chunkNonce(s.base, s.counter), plain, chunkAAD(s.header, s.counter))
	s.counter++
	return writeChunk(s.w, ct)
}

func writeChunk(w io.Writer, ct []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ct)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(ct)
	return err
}

// OpenStream decrypts a chunked container from r into w. Returns the number
// of plaintext bytes written. Wrong passphrase or corruption yields ErrAuth.
func OpenStream(w io.Writer, r io.Reader, passphrase []byte) (int64, error) {
	header := make([]byte, headerLen)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, fmt.Errorf("%w: truncated header", ErrFormat)
	}
	if string(header[0:8]) != string(streamMagic[:]) {
		return 0, fmt.Errorf("%w: bad magic", ErrFormat)
	}
	if v := binary.BigEndian.Uint16(header[8:10]); v != streamVersion {
		return 0, fmt.Errorf("%w: unsupported stream version %d", ErrFormat, v)
	}
	if k := binary.BigEndian.Uint16(header[10:12]); k != kdfArgon2 {
		return 0, fmt.Errorf("%w: unsupported kdf_id %d", ErrFormat, k)
	}
	p := Params{
		M: binary.BigEndian.Uint32(header[12:16]),
		T: binary.BigEndian.Uint32(header[16:20]),
		P: binary.BigEndian.Uint32(header[20:24]),
	}
	if err := p.validateForOpen(); err != nil {
		return 0, err
	}
	if sl := binary.BigEndian.Uint32(header[24:28]); sl != saltLen {
		return 0, fmt.Errorf("%w: salt_len %d", ErrFormat, sl)
	}
	salt := header[28:60]
	baseNonce := header[60:72]

	key := derive(passphrase, salt, p)
	defer zero(key)
	aead, err := newAEAD(key)
	if err != nil {
		return 0, err
	}

	var total int64
	for i := uint64(0); ; i++ {
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			if err == io.EOF {
				return total, fmt.Errorf("%w: нет терминатора", ErrFormat)
			}
			return total, fmt.Errorf("%w: truncated chunk", ErrFormat)
		}
		ctLen := binary.BigEndian.Uint32(lenBuf[:])
		if ctLen < 16 || ctLen > ChunkSize+16 {
			return total, fmt.Errorf("%w: chunk length %d", ErrFormat, ctLen)
		}
		ct := make([]byte, ctLen)
		if _, err := io.ReadFull(r, ct); err != nil {
			return total, fmt.Errorf("%w: truncated chunk data", ErrFormat)
		}
		plain, err := aead.Open(nil, chunkNonce(baseNonce, i), ct, chunkAAD(header, i))
		if err != nil {
			return total, ErrAuth
		}
		if len(plain) == 0 {
			return total, nil // terminator (mandatory: truncation is detected)
		}
		n, err := w.Write(plain)
		total += int64(n)
		if err != nil {
			return total, err
		}
	}
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return aead, nil
}

func chunkNonce(base []byte, counter uint64) []byte {
	n := make([]byte, nonceLen)
	copy(n, base)
	v := binary.BigEndian.Uint64(n[4:12]) ^ counter
	binary.BigEndian.PutUint64(n[4:12], v)
	return n
}

func chunkAAD(header []byte, counter uint64) []byte {
	aad := make([]byte, len(header)+8)
	copy(aad, header)
	binary.BigEndian.PutUint64(aad[len(header):], counter)
	return aad
}
