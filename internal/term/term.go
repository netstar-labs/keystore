// Package term reads a passphrase from the controlling terminal without echo, and
// reports whether a file descriptor is a terminal. It talks to /dev/tty directly, so a
// prompt works even when stdin and stdout are redirected, and never reads a passphrase
// from a pipe.
package term

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

// MaxLen bounds a passphrase read from the terminal.
const MaxLen = 1024

// ErrNoTTY reports that there is no controlling terminal to prompt on.
var ErrNoTTY = errors.New("keystore: no terminal to prompt for a passphrase (set KEYSTORE_PASSPHRASE or use -passfile)")

// IsTerminal reports whether fd refers to a terminal.
func IsTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), ioctlGetTermios)
	return err == nil
}

// ReadPassword writes prompt to the terminal and reads one line with echo disabled.
// The terminal state is restored on return and on SIGINT/SIGTERM during the prompt.
func ReadPassword(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, ErrNoTTY
	}
	defer tty.Close()
	fd := int(tty.Fd())
	old, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return nil, ErrNoTTY
	}
	noEcho := *old
	noEcho.Lflag &^= unix.ECHO
	noEcho.Lflag |= unix.ICANON | unix.ISIG
	noEcho.Iflag |= unix.ICRNL
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, &noEcho); err != nil {
		return nil, err
	}
	restore := func() { _ = unix.IoctlSetTermios(fd, ioctlSetTermios, old) }
	defer restore()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-sig:
			restore()
			fmt.Fprintln(tty)
			os.Exit(130)
		case <-done:
		}
	}()

	fmt.Fprint(tty, prompt)
	line, err := readLine(tty)
	fmt.Fprintln(tty)
	return line, err
}

// readLine reads up to a newline, one byte at a time so nothing past the line is
// consumed, and refuses lines longer than MaxLen.
func readLine(f *os.File) ([]byte, error) {
	var buf [1]byte
	line := make([]byte, 0, MaxLen) // fixed capacity: append never reallocates and copies
	for {
		n, err := f.Read(buf[:])
		if n == 1 {
			if buf[0] == '\n' {
				return bytes.TrimSuffix(line, []byte("\r")), nil
			}
			if len(line) == MaxLen {
				clear(line)
				return nil, errors.New("keystore: passphrase too long")
			}
			line = append(line, buf[0])
		}
		if err != nil {
			if len(line) > 0 {
				return line, nil
			}
			return nil, err
		}
	}
}
