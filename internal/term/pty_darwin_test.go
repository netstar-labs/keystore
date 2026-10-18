package term

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openPTY returns the master of a new pseudo-terminal and the path of its slave.
func openPTY() (*os.File, string, error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, "", err
	}
	fd := m.Fd()
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, fd, unix.TIOCPTYGRANT, 0); e != 0 {
		m.Close()
		return nil, "", e
	}
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, fd, unix.TIOCPTYUNLK, 0); e != 0 {
		m.Close()
		return nil, "", e
	}
	var name [128]byte
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, fd, unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))); e != 0 {
		m.Close()
		return nil, "", e
	}
	n := 0
	for n < len(name) && name[n] != 0 {
		n++
	}
	return m, string(name[:n]), nil
}
