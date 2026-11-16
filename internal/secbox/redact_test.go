package secbox

import (
	"bytes"
	"testing"
)

var secretFixtures = map[string][]byte{
	"json api key":        []byte(`{"provider": {"apiKey": "sk-real-key-1234567890"}}`),
	"jsonc comment":       []byte(`// comment\n{"apiKey": "sk-no-key-required", "model": "mimo"}`),
	"bearer in bak":       []byte(`{"headers": {"Authorization": "Bearer eyJhbGciOi.very.long.token.value"}}`),
	"env file":            []byte("API_KEY=sk-env-key-abcdefghij\nOTHER=plain\n"),
	"assign style":        []byte(`token: ghp_abcdefghij1234567890`),
	"access_token nested": []byte(`"access_token": "ya29.a0AfH_byDMxTokenValue"`),
}

func TestRedactRemovesAllSecretPatterns(t *testing.T) {
	for name, content := range secretFixtures {
		t.Run(name, func(t *testing.T) {
			out := Redact(content)
			if ContainsSecrets(out) {
				t.Fatalf("secret material survived redaction:\n%s", out)
			}
			if bytes.Equal(out, content) {
				t.Fatalf("content unchanged by redaction")
			}
		})
	}
}

func TestRedactKeepsStructure(t *testing.T) {
	in := []byte(`{"model": "xiaomi/mimo", "apiKey": "sk-secret-value-123"}`)
	out := Redact(in)
	if !bytes.Contains(out, []byte(`"model": "xiaomi/mimo"`)) {
		t.Fatalf("non-secret field damaged: %s", out)
	}
	if !bytes.Contains(out, []byte(`"apiKey": "`+RedactedMarker+`"`)) {
		t.Fatalf("marker missing: %s", out)
	}
}

func TestRedactIdempotent(t *testing.T) {
	in := []byte(`{"apiKey": "sk-secret-value-123"}`)
	once := Redact(in)
	twice := Redact(once)
	if !bytes.Equal(once, twice) {
		t.Fatalf("redaction not idempotent:\nonce:  %s\ntwice: %s", once, twice)
	}
}

func TestContainsSecretsOnCleanContent(t *testing.T) {
	clean := []byte(`{"model": "xiaomi/mimo-v2.6-pro", "permission": {"bash": ["*--no-verify*"]}}`)
	if ContainsSecrets(clean) {
		t.Fatalf("false positive on clean content")
	}
}
