//go:build darwin

package ui

import (
	"fmt"
	"syscall"
	"unsafe"
)

// termios helpers (macOS): TIOCGETA/TIOCSETA ioctls via syscall.
type termios syscall.Termios

func termiosGet(fd int) (*termios, bool, error) {
	var t termios
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCGETA, uintptr(unsafe.Pointer(&t)), 0, 0, 0)
	if errno != 0 {
		switch errno {
		case syscall.ENOTTY, syscall.ENODEV, syscall.EOPNOTSUPP:
			return nil, false, nil // not a tty: echo-off is impossible, read plainly
		}
		return nil, false, fmt.Errorf("tcgetattr: %w", errno)
	}
	return &t, true, nil
}

func termiosSet(fd int, t *termios) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCSETA, uintptr(unsafe.Pointer(t)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("tcsetattr: %w", errno)
	}
	return nil
}

// termiosNoEcho turns off terminal echo on t (keeping ECHONL so the newline
// after Enter still moves the cursor).
func termiosNoEcho(t *termios) {
	t.Lflag &^= syscall.ECHO
	t.Lflag |= syscall.ECHONL
}
