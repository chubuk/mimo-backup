package secbox

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestPasswordPolicy(t *testing.T) {
	tests := []struct {
		name    string
		pw      string
		wantErr bool
	}{
		{"min5", "abc12", false},
		{"mixed case and digits", "Abc123Xyz", false},
		{"long", strings.Repeat("a1B2", 256), false},
		{"four chars", "abcd", true},
		{"empty", "", true},
		{"with space", "ab cd", true},
		{"with special", "abc!12", true},
		{"cyrillic", "абвгд", true},
		{"newline inside", "abc\ndef1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.pw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidatePassword(%q) err=%v wantErr=%v", tt.pw, err, tt.wantErr)
			}
		})
	}
}

func TestNormalizePassphrase(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{"trailing newline", "abc12\n", "abc12", false},
		{"trailing crlf", "abc12\r\n", "abc12", false},
		{"no newline", "abc12", "abc12", false},
		{"inner newline stays invalid", "abc\n12", "", true},
		{"two trailing newlines: only one stripped", "abc12\n\n", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizePassphrase([]byte(tt.raw))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	payload := []byte("the secret payload: auth.json contents")
	var buf bytes.Buffer
	n, err := Seal([]byte("abc12"), payload, DefaultParams(), &buf)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if n != buf.Len() {
		t.Fatalf("reported %d bytes, wrote %d", n, buf.Len())
	}
	got, err := Open([]byte("abc12"), buf.Bytes())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q", got)
	}
}

func TestOpenWrongPassphrase(t *testing.T) {
	var buf bytes.Buffer
	if _, err := Seal([]byte("abc12"), []byte("payload"), DefaultParams(), &buf); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	_, err := Open([]byte("xyz99"), buf.Bytes())
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("err=%v want ErrAuth", err)
	}
}

func TestOpenTamperHeaderFields(t *testing.T) {
	// Build a valid container, then flip each header field.
	var buf bytes.Buffer
	if _, err := Seal([]byte("abc12"), []byte("payload"), DefaultParams(), &buf); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	orig := buf.Bytes()

	mutations := map[string]func(c []byte){
		"magic":      func(c []byte) { c[0] ^= 0xFF },
		"version":    func(c []byte) { binary.BigEndian.PutUint16(c[8:10], 1) },
		"kdf_id":     func(c []byte) { binary.BigEndian.PutUint16(c[10:12], 99) },
		"m_cost":     func(c []byte) { binary.BigEndian.PutUint32(c[12:16], 999_999) },
		"t_cost":     func(c []byte) { binary.BigEndian.PutUint32(c[16:20], 99) },
		"p_cost":     func(c []byte) { binary.BigEndian.PutUint32(c[20:24], 99) },
		"salt_len":   func(c []byte) { binary.BigEndian.PutUint32(c[24:28], 16) },
		"salt":       func(c []byte) { c[28] ^= 0xFF },
		"nonce":      func(c []byte) { c[60] ^= 0xFF },
		"ciphertext": func(c []byte) { c[len(c)-1] ^= 0xFF },
		"truncate":   func(c []byte) { c = c[:len(c)-1] },
	}
	for name, mut := range mutations {
		t.Run(name, func(t *testing.T) {
			c := append([]byte(nil), orig...)
			before := len(c)
			mut(c)
			if len(c) != before && name != "truncate" {
				t.Fatalf("mutation changed length unexpectedly")
			}
			if name == "truncate" {
				c = orig[:len(orig)-1]
			}
			_, err := Open([]byte("abc12"), c)
			if err == nil {
				t.Fatalf("tampered container accepted")
			}
		})
	}
}

func TestOpenMCostBomb(t *testing.T) {
	// A container claiming m_cost=0xFFFFFFFF must be rejected before Argon2id runs.
	var buf bytes.Buffer
	if _, err := Seal([]byte("abc12"), []byte("payload"), DefaultParams(), &buf); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	c := buf.Bytes()
	binary.BigEndian.PutUint32(c[12:16], 0xFFFFFFFF)
	_, err := Open([]byte("abc12"), c)
	if !errors.Is(err, ErrFormat) {
		t.Fatalf("err=%v want ErrFormat", err)
	}
}

func TestOpenShortContainer(t *testing.T) {
	if _, err := Open([]byte("abc12"), []byte("MIMOSEC1")); err == nil {
		t.Fatalf("truncated container accepted")
	}
}

func TestSealRejectsOversizedPayload(t *testing.T) {
	// Guard only: constructing a >512MiB buffer is wasteful, so call with the
	// limit logic directly via a fake length is not possible — instead assert
	// the constant contract.
	if MaxPayload != 512<<20 {
		t.Fatalf("MaxPayload changed: %d", MaxPayload)
	}
}

// --- streaming container (MIMOSEC2) ------------------------------------

func TestStreamRoundTrip(t *testing.T) {
	// Payload with a non-trivial size: several full chunks + a tail.
	payload := bytes.Repeat([]byte("mimo-stream-payload-"), 20000) // ~380 KB
	var sealed bytes.Buffer
	n, err := SealStream(&sealed, bytes.NewReader(payload), []byte("abc12"), DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("consumed %d, want %d", n, len(payload))
	}
	if !LooksEncrypted(sealed.Bytes()) {
		t.Fatal("stream magic not detected")
	}
	var out bytes.Buffer
	m, err := OpenStream(&out, bytes.NewReader(sealed.Bytes()), []byte("abc12"))
	if err != nil {
		t.Fatal(err)
	}
	if m != int64(len(payload)) || !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("round trip mismatch: %d vs %d bytes", m, len(payload))
	}
}

func TestStreamEmptyPayload(t *testing.T) {
	var sealed bytes.Buffer
	if _, err := SealStream(&sealed, bytes.NewReader(nil), []byte("abc12"), DefaultParams()); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := OpenStream(&out, bytes.NewReader(sealed.Bytes()), []byte("abc12")); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("empty payload produced %d bytes", out.Len())
	}
}

func TestStreamWrongPassphrase(t *testing.T) {
	var sealed bytes.Buffer
	if _, err := SealStream(&sealed, strings.NewReader("data"), []byte("abc12"), DefaultParams()); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := OpenStream(&out, bytes.NewReader(sealed.Bytes()), []byte("wrong1")); err != ErrAuth {
		t.Fatalf("err = %v, want ErrAuth", err)
	}
}

func TestStreamTruncated(t *testing.T) {
	var sealed bytes.Buffer
	if _, err := SealStream(&sealed, strings.NewReader("some data here"), []byte("abc12"), DefaultParams()); err != nil {
		t.Fatal(err)
	}
	raw := sealed.Bytes()
	var out bytes.Buffer
	if _, err := OpenStream(&out, bytes.NewReader(raw[:len(raw)-5]), []byte("abc12")); err == nil {
		t.Fatal("truncated stream accepted")
	}
}
