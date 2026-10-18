package peercred

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// A connection that is already closed has no descriptor to ask about: UID must report an
// error and -1, never a uid that could match ours.
func TestUIDOfClosedConn(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "pc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := net.Dial("unix", sock); err == nil {
			defer c.Close()
			c.Read(make([]byte, 1))
		}
	}()
	c, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if uid, err := UID(c); err == nil || uid != -1 {
		t.Fatalf("UID(closed) = %d, %v; want -1 and an error", uid, err)
	}
}

// A zero-value *net.UnixConn (no descriptor at all) is refused, not dereferenced.
func TestUIDOfInvalidConn(t *testing.T) {
	if uid, err := UID(&net.UnixConn{}); err == nil || uid != -1 {
		t.Fatalf("UID(zero conn) = %d, %v; want -1 and an error", uid, err)
	}
}

// A unix socket with no peer (never connected) is not a credential: the kernel call
// fails (macOS: ENOTCONN) or, where it succeeds, must not vouch for our uid.
func TestUIDOfUnconnectedSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "pc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: filepath.Join(dir, "d"), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uid, err := UID(c)
	if err == nil && uid == os.Getuid() {
		t.Fatalf("UID(unconnected) = %d, nil: an unconnected socket vouched for our uid", uid)
	}
	if err != nil && uid != -1 {
		t.Fatalf("UID returned %d alongside error %v; want -1", uid, err)
	}
}

func TestUIDIsOurs(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "pc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := net.Dial("unix", sock)
		if err == nil {
			defer c.Close()
			c.Read(make([]byte, 1))
		}
	}()
	c, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uid, err := UID(c)
	if err != nil || uid != os.Getuid() {
		t.Fatalf("UID = %d, %v; want %d", uid, err, os.Getuid())
	}
}
