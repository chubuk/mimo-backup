package secbox

import (
	"fmt"
	"regexp"
	"strings"
)

// Password policy: Latin letters (case-sensitive) + digits only, 5..1024 chars.
// Go's regexp caps repeat counts at 1000, so the upper bound is checked separately.
var passwordRe = regexp.MustCompile(`^[A-Za-z0-9]+$`)

const (
	minPasswordLen = 5
	maxPasswordLen = 1024
)

// ErrPassword reports a password-policy violation.
var ErrPassword = fmt.Errorf("password does not meet requirements: only Latin letters and digits (A-Z a-z 0-9), no spaces or special characters, min 5 characters")

// ValidatePassword enforces the password policy.
func ValidatePassword(pw string) error {
	if len(pw) < minPasswordLen || len(pw) > maxPasswordLen || !passwordRe.MatchString(pw) {
		return ErrPassword
	}
	return nil
}

// NormalizePassphrase strips at most one trailing newline (typical "echo > file")
// and CR, then validates.
func NormalizePassphrase(raw []byte) (string, error) {
	s := string(raw)
	s = strings.TrimSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\r")
	if err := ValidatePassword(s); err != nil {
		return "", err
	}
	return s, nil
}

// PasswordHint is the short hint shown at the prompt.
const PasswordHint = "пароль [мин. 5, лучше 12+ — не перебираемый]"
