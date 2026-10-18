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
	"strings"
	"syscall"
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

// Regression (review F1): a client that keeps one connection busy must not keep the
// agent — and its key — alive past TTL. Expiry closes open connections.
func TestTTLNotExtendedByPersistentConnection(t *testing.T) {
	r := start(t, func(s *Server) { s.TTL = 300 * time.Millisecond })
	conn, err := net.Dial("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	signedAfterTTL := 0
	start := time.Now()
	for time.Now().Before(deadline) {
		if writeFrame(conn, OpSign, []byte("keepalive")) != nil {
			break
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		st, _, err := readFrame(conn)
		if err != nil || st != StatusOK {
			break
		}
		if time.Since(start) > 500*time.Millisecond {
			signedAfterTTL++
		}
		time.Sleep(50 * time.Millisecond)
	}
	if signedAfterTTL > 0 {
		t.Fatalf("agent signed %d requests after its TTL on a persistent connection", signedAfterTTL)
	}
	select {
	case err := <-r.done:
		if !errors.Is(err, ErrExpired) {
			t.Fatalf("Serve = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve still running after TTL with a persistent connection")
	}
}

// Close (SIGTERM) must also end open connections promptly.
func TestCloseEndsPersistentConnection(t *testing.T) {
	r := start(t, nil)
	conn, _ := net.Dial("unix", r.sock)
	defer conn.Close()
	writeFrame(conn, OpPublic, nil)
	readFrame(conn)
	r.srv.Close()
	select {
	case <-r.done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve blocked on an open connection after Close")
	}
}

// Regression (review F4): two agents racing over a stale socket could both "win", the
// second unlinking the first's fresh socket and orphaning an agent that holds the key.
func TestConcurrentListenOneWinner(t *testing.T) {
	dir := sockDir(t)
	sock := filepath.Join(dir, "a.sock")
	for trial := 0; trial < 2000; trial++ {
		stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		stale.SetUnlinkOnClose(false)
		stale.Close()
		type res struct {
			ln  *Listener
			err error
		}
		ch := make(chan res, 2)
		for i := 0; i < 2; i++ {
			go func() { ln, err := Listen(sock); ch <- res{ln, err} }()
		}
		a, b := <-ch, <-ch
		won := 0
		for _, r := range []res{a, b} {
			if r.err == nil {
				won++
			}
		}
		if won != 1 {
			t.Fatalf("trial %d: %d agents won the socket (errs: %v / %v)", trial, won, a.err, b.err)
		}
		for _, r := range []res{a, b} {
			if r.ln != nil {
				r.ln.Close()
			}
		}
		os.Remove(sock)
	}
}

// A negative TTL or Idle used to be accepted and silently meant "no limit" (the timers
// are armed only for values > 0), so a wrapper computing -ttl from a deadline that had
// already passed started an agent that never expired.
func TestNegativeLifetimeRejected(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ttl, idle time.Duration
	}{
		{"negative ttl", -time.Second, 0},
		{"negative idle", 0, -time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, priv, _ := ed25519.GenerateKey(nil)
			srv, err := NewServer(priv)
			if err != nil {
				t.Fatal(err)
			}
			srv.TTL, srv.Idle = tc.ttl, tc.idle
			sock := filepath.Join(sockDir(t), "agent.sock")
			ln, err := Listen(sock)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- srv.Serve(ln) }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("Serve returned nil for a negative lifetime")
				}
			case <-time.After(2 * time.Second):
				srv.Close()
				t.Fatal("Serve accepted a negative lifetime and runs unbounded")
			}
			if _, err := os.Lstat(sock); err == nil {
				t.Error("socket left behind after a rejected configuration")
			}
		})
	}
}

// Out of file descriptors is a transient condition: Serve used to return on it without
// closing the listener or the open connections, leaving either a dead agent holding a
// stale socket, or (while any client kept a connection busy) a zombie that no longer
// accepted but still held the key.
func TestAcceptEMFILEIsRetried(t *testing.T) {
	fail := make(chan struct{}, 1)
	fail <- struct{}{}
	r := start(t, func(s *Server) {
		s.accept = func(ln *Listener) (*net.UnixConn, error) {
			select {
			case <-fail:
				return nil, &net.OpError{Op: "accept", Err: os.NewSyscallError("accept", syscall.EMFILE)}
			default:
				return ln.AcceptUnix()
			}
		}
	})
	c, err := Dial(r.sock)
	if err != nil {
		t.Fatalf("agent did not survive EMFILE on accept: %v", err)
	}
	if _, err := c.Sign(nil, []byte("m"), crypto.Hash(0)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-r.done:
		t.Fatalf("Serve returned after a transient accept error: %v", err)
	default:
	}
}

func TestAcceptFatalErrorStopsEverything(t *testing.T) {
	boom := errors.New("boom")
	fail := make(chan struct{})
	r := start(t, func(s *Server) {
		s.accept = func(ln *Listener) (*net.UnixConn, error) {
			select {
			case <-fail:
				return nil, boom
			default:
				return ln.AcceptUnix()
			}
		}
	})
	// A client that keeps a connection open must not be able to hold a dead accept loop.
	held, err := net.Dial("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if _, err := Dial(r.sock); err != nil { // makes sure the held connection is accepted first
		t.Fatal(err)
	}
	close(fail)
	// the accept loop is blocked in the real AcceptUnix: wake it with one more connection
	net.Dial("unix", r.sock)
	select {
	case err := <-r.done:
		if !errors.Is(err, boom) {
			t.Fatalf("Serve = %v, want the accept error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return (or is waiting on an open connection)")
	}
	if _, err := os.Lstat(r.sock); err == nil {
		t.Error("socket left behind after a fatal accept error")
	}
	held.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := held.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("open connection was not closed by the stopping agent: %v", err)
	}
}

// A socket path longer than sun_path used to fail inside bind with "invalid argument"
// (naming no limit), after the path's lock file had already been created and left behind.
func TestListenRejectsTooLongPathWithoutSideEffects(t *testing.T) {
	dir := sockDir(t)
	long := filepath.Join(dir, strings.Repeat("s", 200)+".sock")
	_, err := Listen(long)
	if err == nil {
		t.Fatal("Listen accepted a path longer than sun_path")
	}
	if !strings.Contains(err.Error(), "at most") {
		t.Errorf("error does not name the limit: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*")); len(left) != 0 {
		t.Errorf("rejected path left files behind: %v", left)
	}
	// The longest path that fits still works.
	max := len(syscall.RawSockaddrUnix{}.Path) - 1
	name := strings.Repeat("s", max-len(dir)-1)
	ln, err := Listen(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("a path of exactly %d bytes was refused: %v", max, err)
	}
	ln.Close()
}
