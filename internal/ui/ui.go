// Package ui implements terminal interaction: prompts with defaults,
// no-echo password entry (Linux termios), progress reporting, and
// archive auto-discovery for the interactive wizard.
package ui

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/chubuk/mimo-backup/internal/secbox"
)

// UI reads from stdin and writes prompts to stderr (keeps stdout clean for data).
type UI struct {
	in  *bufio.Reader
	out io.Writer
}

// New returns a UI bound to the process streams.
func New() *UI {
	return &UI{in: bufio.NewReader(os.Stdin), out: os.Stderr}
}

// Ask prints "prompt [default]: " and reads one line. Empty input returns def.
func (u *UI) Ask(prompt, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(u.out, "%s [%s]: ", prompt, def)
	} else {
		fmt.Fprintf(u.out, "%s: ", prompt)
	}
	line, err := u.in.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def, nil
	}
	return line, nil
}

// Confirm asks a yes/no question; empty input returns defYes.
func (u *UI) Confirm(prompt string, defYes bool) (bool, error) {
	hint := "Y/n"
	if !defYes {
		hint = "y/N"
	}
	fmt.Fprintf(u.out, "%s [%s]: ", prompt, hint)
	line, err := u.in.ReadString('\n')
	if err != nil && line == "" {
		return false, err
	}
	line = strings.ToLower(strings.TrimSpace(line))
	switch line {
	case "":
		return defYes, nil
	case "y", "yes", "д", "да":
		return true, nil
	case "n", "no", "н", "нет":
		return false, nil
	}
	return defYes, nil
}

// Choose prints numbered options and returns the selected index (0-based).
// Empty input selects defIdx.
func (u *UI) Choose(prompt string, options []string, defIdx int) (int, error) {
	fmt.Fprintf(u.out, "%s\n", prompt)
	for i, opt := range options {
		marker := "  "
		if i == defIdx {
			marker = "> "
		}
		fmt.Fprintf(u.out, "%s%d) %s\n", marker, i+1, opt)
	}
	fmt.Fprintf(u.out, "Выбор [%d]: ", defIdx+1)
	line, err := u.in.ReadString('\n')
	if err != nil && line == "" {
		return 0, err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return defIdx, nil
	}
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(options) {
		return 0, fmt.Errorf("неверный выбор %q", line)
	}
	return n - 1, nil
}

// ReadPassword reads a password with terminal echo off. It is used for both
// entry and confirmation; callers loop on mismatch.
func (u *UI) ReadPassword(prompt string) (string, error) {
	fmt.Fprintf(u.out, "%s: ", prompt)

	fd := int(os.Stdin.Fd())
	old, isTTY, err := termiosGet(fd)
	if err != nil {
		return "", err
	}
	if isTTY {
		noecho := *old
		noecho.Lflag &^= syscall.ECHO
		noecho.Lflag |= syscall.ECHONL
		if err := termiosSet(fd, &noecho); err != nil {
			return "", err
		}
		defer termiosSet(fd, old)
	}

	line, err := u.in.ReadString('\n')
	fmt.Fprintln(u.out)
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// ReadPasswordNew asks twice (creation) and validates the policy, looping
// until both entries match and are valid.
func (u *UI) ReadPasswordNew() (string, error) {
	for {
		p1, err := u.ReadPassword(secbox.PasswordHint)
		if err != nil {
			return "", err
		}
		if err := secbox.ValidatePassword(p1); err != nil {
			fmt.Fprintf(u.out, "Ошибка: %v\n", err)
			continue
		}
		p2, err := u.ReadPassword("повторите пароль")
		if err != nil {
			return "", err
		}
		if p1 != p2 {
			fmt.Fprintln(u.out, "Пароли не совпадают — попробуйте ещё раз.")
			continue
		}
		return p1, nil
	}
}

// ReadPasswordOnce reads and validates a single password (restore/unlock).
func (u *UI) ReadPasswordOnce() (string, error) {
	pw, err := u.ReadPassword(secbox.PasswordHint)
	if err != nil {
		return "", err
	}
	if err := secbox.ValidatePassword(pw); err != nil {
		return "", err
	}
	return pw, nil
}

// termios helpers (Linux): TCGETS/TCSETS ioctls via syscall.
type termios syscall.Termios

func termiosGet(fd int) (*termios, bool, error) {
	var t termios
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), syscall.TCGETS, uintptr(unsafe.Pointer(&t)), 0, 0, 0)
	if errno != 0 {
		if errno == syscall.ENOTTY {
			return nil, false, nil // not a tty: echo-off is impossible, read plainly
		}
		return nil, false, fmt.Errorf("tcgets: %w", errno)
	}
	return &t, true, nil
}

func termiosSet(fd int, t *termios) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), syscall.TCSETS, uintptr(unsafe.Pointer(t)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("tcsets: %w", errno)
	}
	return nil
}

// ErrNotTTY reports password input attempted without a terminal.
var ErrNotTTY = errors.New("нет терминала для ввода пароля: используйте --passphrase-file или $MIMO_BACKUP_PASSPHRASE")

// FindArchives scans common locations for mimo-backup artifacts and returns
// candidate archives (main tar.gz and secrets containers) with metadata.
type ArchiveInfo struct {
	Path    string
	Size    int64
	ModTime time.Time
	Kind    string // "main" | "secrets"
}

// DiscoverArchives looks in cwd, beside the executable, and on removable mounts.
func DiscoverArchives() []ArchiveInfo {
	dirs := []string{"."}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	home, _ := os.UserHomeDir()
	user := filepath.Base(home)
	for _, base := range []string{
		"/media/" + user,
		"/run/media/" + user,
		"/mnt",
	} {
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				dirs = append(dirs, filepath.Join(base, e.Name()))
			}
		}
	}

	seen := map[string]bool{}
	var out []ArchiveInfo
	for _, d := range dirs {
		matches, _ := filepath.Glob(filepath.Join(d, "mimo-backup-*"))
		for _, m := range matches {
			if seen[m] {
				continue
			}
			seen[m] = true
			fi, err := os.Stat(m)
			if err != nil || fi.IsDir() {
				continue
			}
			kind := ""
			switch {
			case strings.HasSuffix(m, ".tar.gz"):
				kind = "main"
			case strings.HasSuffix(m, ".mimosec") || strings.HasSuffix(m, "-secrets.tar.gz"):
				kind = "secrets"
			default:
				continue
			}
			out = append(out, ArchiveInfo{Path: m, Size: fi.Size(), ModTime: fi.ModTime(), Kind: kind})
		}
	}
	return out
}
