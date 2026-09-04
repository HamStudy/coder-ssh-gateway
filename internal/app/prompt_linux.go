//go:build linux

package app

import (
	"bufio"
	"os"
	"syscall"
	"unsafe"
)

func readHiddenTTYLine() (string, error) {
	return readTTY(termiosOff)
}

func readTTYLine() (string, error) {
	return readTTY(nil)
}

// readTTY reads one line from /dev/tty, optionally applying mutate to the
// terminal attributes for the duration of the read (echo off for secrets).
func readTTY(mutate func(*syscall.Termios)) (line string, err error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", err
	}
	defer tty.Close()
	fd := tty.Fd()

	if mutate != nil {
		var old syscall.Termios
		if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&old)), 0, 0, 0); errno != 0 {
			return "", errno
		}
		raw := old
		mutate(&raw)
		if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&raw)), 0, 0, 0); errno != 0 {
			return "", errno
		}
		defer func() {
			syscall.Syscall6(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&old)), 0, 0, 0)
		}()
	}
	line, err = bufio.NewReader(tty).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return trimLineEnd(line), nil
}

func termiosOff(t *syscall.Termios) {
	t.Lflag &^= syscall.ECHO
}
