package secbox

import (
	"bytes"
	"regexp"
)

// RedactedMarker replaces secret values in plaintext (main-archive) copies.
const RedactedMarker = "***REDACTED***"

var redactedValue = []byte(`"` + RedactedMarker + `"`)
var redactedValueBare = []byte(RedactedMarker)

// secretKeyRe matches JSON/JSONC "key": value pairs whose values are secrets.
// Group 1 = key and separator, group 2 = value.
var secretKeyRe = regexp.MustCompile(`(?i)("?(?:api[-_]?key|apikey|token|access[-_]?token|authorization|password|passwd|secret|client[-_]?secret|private[-_]?key)"?\s*:\s*)("[^"]*"|'[^']*'|[^\s,;}\]]+)`)

// secretAssignRe matches key=value / key: value style secrets (env, ini, .bak).
var secretAssignRe = regexp.MustCompile(`(?i)((?:api[-_]?key|apikey|token|access[-_]?token|authorization|password|passwd|secret|client[-_]?secret|private[-_]?key)\s*[=:]\s*)("[^"]*"|'[^']*'|\S+)`)

// bearerRe catches inline bearer material in arbitrary text.
var bearerRe = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9\-._~+/=]{8,}`)

// skRe catches OpenAI-style key literals.
var skRe = regexp.MustCompile(`\bsk-[A-Za-z0-9\-._~+/=]{8,}`)

// Redact replaces secret values in content with RedactedMarker, preserving
// surrounding structure and comments. Safe for JSON, JSONC and plain text.
func Redact(content []byte) []byte {
	out := secretKeyRe.ReplaceAll(content, []byte("${1}"+`"`+RedactedMarker+`"`))
	out = secretAssignRe.ReplaceAll(out, []byte("${1}"+RedactedMarker))
	out = bearerRe.ReplaceAll(out, []byte("${1}"+RedactedMarker))
	out = skRe.ReplaceAll(out, []byte(RedactedMarker))
	return out
}

// ContainsSecrets reports whether content still holds secret material
// (redacted markers excluded). Test gate and belt-and-braces check before
// writing main-archive copies.
func ContainsSecrets(content []byte) bool {
	if bearerRe.Match(content) || skRe.Match(content) {
		return true
	}
	for _, re := range []*regexp.Regexp{secretKeyRe, secretAssignRe} {
		for _, m := range re.FindAllSubmatch(content, -1) {
			val := bytes.TrimSpace(m[2])
			if bytes.Equal(val, redactedValue) || bytes.Equal(val, redactedValueBare) {
				continue
			}
			return true
		}
	}
	return false
}
