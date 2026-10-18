package peercred

import "golang.org/x/sys/unix"

func peerUID(fd int) (int, error) {
	c, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return -1, err
	}
	return int(c.Uid), nil
}
