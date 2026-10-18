package agent

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netstar-labs/keystore/internal/kdf"
	"github.com/netstar-labs/keystore/pkg/keystore"
)

func TestMain(m *testing.M) {
	kdf.Default = kdf.Cost{Mem: kdf.MinMem, Time: 1, Par: 1}
	os.Exit(m.Run())
}

// sockDir returns a short 0700 directory: unix socket paths are limited to ~104 bytes
// on Darwin, and t.TempDir() under $TMPDIR is too long.
func sockDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "ka")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

type running struct {
	srv  *Server
	sock string
	done chan error
	pub  ed25519.PublicKey
}

func start(t *testing.T, configure func(*Server)) *running {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv, err := NewServer(priv)
	if err != nil {
		t.Fatal(err)
	}
	if configure != nil {
		configure(srv)
	}
	sock := filepath.Join(sockDir(t), "agent.sock")
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	r := &running{srv: srv, sock: sock, done: make(chan error, 1), pub: pub}
	go func() { r.done <- srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	return r
}

func TestSignOverSocketVerifies(t *testing.T) {
	r := start(t, nil)
	c, err := Dial(r.sock)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Public().(ed25519.PublicKey).Equal(r.pub) {
		t.Fatal("client public key differs from the agent's")
	}
	for _, msg := range [][]byte{[]byte("hello"), nil, bytes.Repeat([]byte{7}, MaxPayload)} {
		sig, err := c.Sign(nil, msg, crypto.Hash(0))
		if err != nil {
			t.Fatalf("Sign(%d bytes): %v", len(msg), err)
		}
		if !ed25519.Verify(r.pub, msg, sig) {
			t.Fatal("signature does not verify")
		}
	}
	var s crypto.Signer = c // the client is a crypto.Signer
	_ = s
}

func TestSocketModeAndCleanup(t *testing.T) {
	r := start(t, nil)
	st, err := os.Stat(r.sock)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v, want 0600", st.Mode().Perm())
	}
	r.srv.Close()
	if err := <-r.done; err != nil {
		t.Fatalf("Serve after Close = %v", err)
	}
	if _, err := os.Lstat(r.sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket not removed on close: %v", err)
	}
}

func TestRefusesLiveSocketRemovesStale(t *testing.T) {
	r := start(t, nil)
	if _, err := Listen(r.sock); !errors.Is(err, ErrInUse) {
		t.Fatalf("second Listen on a live socket = %v, want ErrInUse", err)
	}
	// A stale socket (nobody listening) is replaced.
	dir := sockDir(t)
	stale := filepath.Join(dir, "stale.sock")
	ln, _ := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	ln.SetUnlinkOnClose(false)
	ln.Close()
	if _, err := os.Lstat(stale); err != nil {
		t.Fatalf("setup: stale socket missing: %v", err)
	}
	ln2, err := Listen(stale)
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	ln2.Close()
	// A regular file is never removed.
	reg := filepath.Join(dir, "file")
	os.WriteFile(reg, []byte("x"), 0o600)
	if _, err := Listen(reg); err == nil {
		t.Fatal("Listen replaced a regular file")
	}
}

func TestSocketDirMustBePrivate(t *testing.T) {
	dir := sockDir(t)
	os.Chmod(dir, 0o755)
	if _, err := Listen(filepath.Join(dir, "a.sock")); err == nil {
		t.Fatal("Listen accepted a 0755 parent directory")
	}
}

func TestWrongUIDPeerRejected(t *testing.T) {
	r := start(t, func(s *Server) {
		s.uidOf = func(*net.UnixConn) (int, error) { return os.Getuid() + 1, nil }
	})
	if _, err := Dial(r.sock); err == nil {
		t.Fatal("agent served a peer with a different uid")
	}
}

func TestOversizeFrameRejected(t *testing.T) {
	r := start(t, nil)
	conn, err := net.Dial("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	hdr := []byte{OpSign, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(hdr[1:], MaxPayload+1)
	conn.Write(hdr)
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	status, _, err := readFrame(conn)
	if err != nil || status != StatusErr {
		t.Fatalf("oversize frame: status %d, %v", status, err)
	}
	c, _ := Dial(r.sock)
	if _, err := c.Sign(nil, make([]byte, MaxPayload+1), crypto.Hash(0)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("client sent an oversize message: %v", err)
	}
}

func TestUnknownOpRejected(t *testing.T) {
	r := start(t, nil)
	conn, _ := net.Dial("unix", r.sock)
	defer conn.Close()
	writeFrame(conn, 'X', nil)
	status, _, err := readFrame(conn)
	if err != nil || status != StatusErr {
		t.Fatalf("unknown op: status %d, %v", status, err)
	}
}

func TestTTLExpiry(t *testing.T) {
	r := start(t, func(s *Server) { s.TTL = 200 * time.Millisecond })
	if _, err := Dial(r.sock); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-r.done:
		if !errors.Is(err, ErrExpired) {
			t.Fatalf("Serve = %v, want ErrExpired", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent outlived its TTL")
	}
	if _, err := os.Lstat(r.sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("socket left behind after TTL")
	}
	if _, err := Dial(r.sock); err == nil {
		t.Fatal("expired agent still answers")
	}
}

func TestIdleExpiryResetByUse(t *testing.T) {
	r := start(t, func(s *Server) { s.Idle = 300 * time.Millisecond })
	c, _ := Dial(r.sock)
	// Keep it busy past several idle windows.
	for i := 0; i < 6; i++ {
		time.Sleep(100 * time.Millisecond)
		if _, err := c.Sign(nil, []byte("keepalive"), crypto.Hash(0)); err != nil {
			t.Fatalf("agent expired while in use: %v", err)
		}
	}
	select {
	case err := <-r.done:
		if !errors.Is(err, ErrExpired) {
			t.Fatalf("Serve = %v, want ErrExpired", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("idle agent did not expire")
	}
}

func TestClientRejectsPrehashAndContext(t *testing.T) {
	r := start(t, nil)
	c, _ := Dial(r.sock)
	h := sha512.Sum512([]byte("m"))
	if _, err := c.Sign(nil, h[:], crypto.SHA512); err == nil {
		t.Fatal("prehashed Ed25519 accepted")
	}
	if _, err := c.Sign(nil, []byte("m"), &ed25519.Options{Context: "ctx"}); err == nil {
		t.Fatal("Ed25519 context accepted")
	}
	if _, err := c.Sign(nil, []byte("m"), &ed25519.Options{}); err != nil {
		t.Fatalf("plain ed25519.Options rejected: %v", err)
	}
}

func TestAbsentAgent(t *testing.T) {
	if _, err := Dial(filepath.Join(sockDir(t), "none.sock")); err == nil {
		t.Fatal("Dial to a missing socket succeeded")
	}
}

func TestResolveSigner(t *testing.T) {
	r := start(t, nil)
	s, err := ResolveSigner(r.sock, "", "", func() ([]byte, error) {
		t.Fatal("passphrase requested for the agent path")
		return nil, nil
	})
	if err != nil || !s.Public().(ed25519.PublicKey).Equal(r.pub) {
		t.Fatalf("agent path: %v", err)
	}
	ring := filepath.Join(t.TempDir(), "r.ks")
	k, _ := keystore.Create(ring)
	pass := []byte("resolve test passphrase")
	pub, _ := k.Add("a", pass)
	s, err = ResolveSigner("", ring, "", func() ([]byte, error) { return append([]byte(nil), pass...), nil })
	if err != nil || !s.Public().(ed25519.PublicKey).Equal(pub) {
		t.Fatalf("ring path: %v", err)
	}
}

// Regression: Close before Serve once left Serve blocked in Accept forever.
func TestCloseBeforeServe(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	srv, _ := NewServer(priv)
	sock := filepath.Join(sockDir(t), "a.sock")
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve blocked after an earlier Close")
	}
	if _, err := os.Lstat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("socket left behind")
	}
}
