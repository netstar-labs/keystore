// Package peercred reports the user id of the process on the other end of a unix
// socket, as the kernel recorded it at connect time (SO_PEERCRED on Linux,
// LOCAL_PEERCRED on Darwin). It cannot be forged by the peer.
package peercred

import (
	"errors"
	"net"
)

// ErrUnsupported reports a platform without peer credentials.
var ErrUnsupported = errors.New("keystore: peer credentials are not supported on this platform")

// UID returns the effective user id of conn's peer.
func UID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid, cerr := -1, error(nil)
	if err := raw.Control(func(fd uintptr) { uid, cerr = peerUID(int(fd)) }); err != nil {
		return -1, err
	}
	return uid, cerr
}
