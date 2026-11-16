//go:build linux

package ui

import (
	"fmt"
	"syscall"
	"unsafe"
)

// termios helpers (Linux): TCGETS/TCSETS ioctls via syscall.
type termios syscall.Termios

func termiosGet(fd int) (*termios, bool, error) {
	var t termios
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), syscall.TCGETS, uintptr(unsafe.Pointer(&t)), 0, 0, 0)
	if errno != 0 {
		switch errno {
		case syscall.ENOTTY, syscall.ENODEV, syscall.EOPNOTSUPP:
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

// termiosNoEcho turns off terminal echo on t (keeping ECHONL so the newline
// after Enter still moves the cursor).
func termiosNoEcho(t *termios) {
	t.Lflag &^= syscall.ECHO
	t.Lflag |= syscall.ECHONL
}
