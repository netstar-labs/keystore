package peercred

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

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
