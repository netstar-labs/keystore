package agent

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

// Real timers (no fake clock): the integration check that Server wires time.AfterFunc
// correctly; the expiry semantics are asserted on a fake clock in clock_test.go.
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

// Real timers; see TestTTLExpiry.
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

// A rejected peer used to be logged with a trailing "<nil>" (the lookup error, when the
// uid simply differed), which read as a failure of the logging itself.
func TestRejectedPeerLogLineIsClean(t *testing.T) {
	logged := make(chan string, 4)
	r := start(t, func(s *Server) {
		s.uidOf = func(*net.UnixConn) (int, error) { return os.Getuid() + 1, nil }
		s.Log = func(format string, args ...any) { logged <- fmt.Sprintf(format, args...) }
	})
	Dial(r.sock)
	select {
	case line := <-logged:
		if !strings.Contains(line, "peer uid") || strings.Contains(line, "<nil>") {
			t.Errorf("log line %q: want the uids and no <nil>", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("rejection was not logged")
	}
}

// When the peer's uid cannot be looked up at all, the log says that (the uid is meaningless
// then) and carries the error, rather than a mismatch line with a made-up uid.
func TestPeerUIDLookupFailureIsLoggedAsSuch(t *testing.T) {
	logged := make(chan string, 4)
	r := start(t, func(s *Server) {
		s.uidOf = func(*net.UnixConn) (int, error) { return 0, errors.New("no credentials for this peer") }
		s.Log = func(format string, args ...any) { logged <- fmt.Sprintf(format, args...) }
	})
	if _, err := Dial(r.sock); err == nil {
		t.Fatal("agent served a peer whose uid could not be established")
	}
	select {
	case line := <-logged:
		if !strings.Contains(line, "lookup failed") || !strings.Contains(line, "no credentials for this peer") || strings.Contains(line, "want") {
			t.Errorf("log line %q: want a lookup-failure line carrying the error", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lookup failure was not logged")
	}
}

// The directory error printed Perm() with %v (-rwxr-xr-x) beside a message saying 0700.
func TestSocketDirErrorShowsOctalMode(t *testing.T) {
	dir := sockDir(t)
	os.Chmod(dir, 0o755)
	_, err := Listen(filepath.Join(dir, "a.sock"))
	if err == nil || !strings.Contains(err.Error(), "0755") || !strings.Contains(err.Error(), "0700") {
		t.Errorf("error %v, want both the actual mode 0755 and the required 0700", err)
	}
}

// The agent's error reply is bytes from the other end of the socket; the client must not
// print them raw (a same-uid squatter at the path could send terminal escapes).
func TestClientQuotesTheAgentsErrorText(t *testing.T) {
	sock := filepath.Join(sockDir(t), "fake.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		readFrame(c)
		writeFrame(c, StatusErr, []byte("boom\x1b[31m\r\nkeystore: verified: FORGED"))
	}()
	_, err = Dial(sock)
	if err == nil {
		t.Fatal("Dial succeeded against an error reply")
	}
	for _, r := range err.Error() {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("raw control character %U in error %q", r, err)
		}
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("error lost the agent's message: %q", err)
	}
}

// The escaping above does not bound the text: a fake agent can answer with a megabyte of
// escapes and flood the terminal. The client shows the first 256 raw bytes, escaped, and
// "..." after the closing quote when it cut. The rows compare the whole error, so a moved
// cap, an off-by-one, a missing marker or a cut applied after quoting (which could end
// mid-escape) each fail.
func TestClientBoundsTheAgentsErrorText(t *testing.T) {
	const prefix = "keystore agent: "
	for _, tc := range []struct {
		name    string
		payload []byte
		shown   int // raw bytes expected to be shown
		cut     bool
	}{
		{"255 bytes", bytes.Repeat([]byte("A"), 255), 255, false},
		{"256 bytes", bytes.Repeat([]byte("A"), 256), 256, false},
		{"257 bytes", bytes.Repeat([]byte("A"), 257), 256, true},
		{"1 MiB of ASCII", bytes.Repeat([]byte("A"), MaxPayload), 256, true},
		{"1 MiB of escapes", bytes.Repeat([]byte("\x1b[31mX\n"), MaxPayload/7), 256, true},
		// Every byte quotes to 4 characters; a cut after quoting would land mid-escape.
		{"control bytes", bytes.Repeat([]byte{0x01}, 400), 256, true},
		// "é" is two bytes straddling byte 256: the first half is shown as \xc3, safely.
		{"rune across the cut", append(bytes.Repeat([]byte("A"), 255), []byte("é and more")...), 256, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock := filepath.Join(sockDir(t), "fake.sock")
			ln, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				readFrame(c)
				writeFrame(c, StatusErr, tc.payload)
			}()
			_, err = Dial(sock)
			if err == nil {
				t.Fatal("Dial succeeded against an error reply")
			}
			want := prefix + strconv.Quote(string(tc.payload[:tc.shown]))
			if tc.cut {
				want += "..."
			}
			if err.Error() != want {
				t.Errorf("error (%d bytes) = %.120q...\nwant (%d bytes) %.120q...", len(err.Error()), err, len(want), want)
			}
			if len(err.Error()) > 1100 { // worst case: 256 bytes at 4 characters each, plus framing
				t.Errorf("client error is %d bytes, want at most 1100", len(err.Error()))
			}
			for _, r := range err.Error() {
				if r < 0x20 || r == 0x7f {
					t.Fatalf("raw control character %U in error %.80q", r, err)
				}
			}
		})
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
	// The longest path that fits still works, and one byte more is refused (sun_path
	// holds the NUL too): a limit one too high would fail in bind with "invalid argument"
	// and leave the lock file behind, which is the original bug.
	max := len(syscall.RawSockaddrUnix{}.Path) - 1
	over := filepath.Join(dir, strings.Repeat("s", max+1-len(dir)-1))
	if len(over) != max+1 {
		t.Fatalf("test setup: path is %d bytes, want %d", len(over), max+1)
	}
	if _, err := Listen(over); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("a path of %d bytes: err = %v, want the limit error", max+1, err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*")); len(left) != 0 {
		t.Errorf("max+1 path left files behind: %v", left)
	}
	fits := filepath.Join(dir, strings.Repeat("s", max-len(dir)-1))
	ln, err := Listen(fits)
	if err != nil {
		t.Fatalf("a path of exactly %d bytes was refused: %v", max, err)
	}
	ln.Close()
}

// Listen narrows the process umask around bind so the socket is never reachable by
// others. Unserialised, concurrent calls interleaved set and restore, so a later
// "restore" wrote back another goroutine's temporary 0177 and the process kept it.
func TestConcurrentListenRestoresUmask(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
	dir := sockDir(t)
	for round := 0; round < 50; round++ {
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				ln, err := Listen(filepath.Join(dir, fmt.Sprintf("s%d.sock", i)))
				if err == nil {
					ln.Close()
				}
			}(i)
		}
		wg.Wait()
		if got := syscall.Umask(0o022); got != 0o022 {
			t.Fatalf("round %d: umask left at %#o, want 022", round, got)
		}
	}
}

// Same hazard as the ring's lock file: under a restrictive umask the agent's path lock was
// created 0400, so the NEXT agent start failed with permission denied until it was removed.
func TestAgentLockFileIsUsableUnderARestrictiveUmask(t *testing.T) {
	dir := sockDir(t) // before the umask change
	old := syscall.Umask(0o277)
	defer syscall.Umask(old)
	sock := filepath.Join(dir, "a.sock")
	for i := 0; i < 2; i++ {
		ln, err := Listen(sock)
		if err != nil {
			t.Fatalf("Listen #%d under umask 0277: %v", i+1, err)
		}
		ln.Close()
	}
	st, err := os.Stat(sock + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("agent lock file mode %04o, want 0600", st.Mode().Perm())
	}
}

// If the socket file disappears (a tmp cleaner, a stray rm) the agent used to stay up
// holding the key: accept on an unlinked listener never errors, nothing could reach it, its
// path lock blocked a replacement, and with -ttl 0 -idle 0 (the service units) it never ended.
func TestAgentStopsWhenItsSocketIsRemoved(t *testing.T) {
	logged := make(chan string, 8)
	r := start(t, func(s *Server) {
		s.checkEvery = 20 * time.Millisecond
		s.Log = func(format string, args ...any) { logged <- fmt.Sprintf(format, args...) }
	})
	held, err := net.Dial("unix", r.sock) // a persistent client must not keep the agent alive either
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := os.Remove(r.sock); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-r.done:
		if !errors.Is(err, errSocketLost) {
			t.Fatalf("Serve = %v, want errSocketLost", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent kept running after its socket was removed")
	}
	select {
	case line := <-logged:
		if !strings.Contains(line, "socket") {
			t.Errorf("log line %q does not say the socket was lost", line)
		}
	default:
		t.Error("nothing was logged")
	}
	held.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := held.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("open connection not closed by the stopping agent: %v", err)
	}
	// With the socket gone the path lock is released too: a fresh agent can start.
	ln, err := Listen(r.sock)
	if err != nil {
		t.Fatalf("a replacement agent cannot start: %v", err)
	}
	ln.Close()
}

// Replaced (not removed) must be noticed too, and the stopping agent must not unlink
// whatever now sits at the path: that file is not its socket any more.
func TestAgentStopsWhenItsSocketIsReplacedAndLeavesTheReplacementAlone(t *testing.T) {
	r := start(t, func(s *Server) { s.checkEvery = 20 * time.Millisecond })
	if err := os.Remove(r.sock); err != nil {
		t.Fatal(err)
	}
	other, err := net.Listen("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	select {
	case err := <-r.done:
		if !errors.Is(err, errSocketLost) {
			t.Fatalf("Serve = %v, want errSocketLost", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent kept running after its socket was replaced")
	}
	if _, err := os.Lstat(r.sock); err != nil {
		t.Errorf("the stopping agent unlinked the file that replaced its socket: %v", err)
	}
}

// A Close that races the socket check must stay a clean stop: Close itself unlinks the
// socket, which the check must not mistake for a loss (Serve returning errSocketLost, a
// false "socket lost" exit 1 on SIGTERM), and must not race Close on the unlink flag.
func TestCloseRacingTheSocketCheckIsACleanStop(t *testing.T) {
	for i := 0; i < 300; i++ {
		r := start(t, func(s *Server) { s.checkEvery = 50 * time.Microsecond })
		time.Sleep(time.Duration(i%7) * 40 * time.Microsecond)
		r.srv.Close()
		select {
		case err := <-r.done:
			if err != nil {
				t.Fatalf("run %d: Serve after Close = %v, want nil", i, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("run %d: Serve did not return", i)
		}
		ln, err := Listen(r.sock) // the path lock must be free the moment Serve returned
		if err != nil {
			t.Fatalf("run %d: replacement cannot start: %v", i, err)
		}
		ln.Close()
	}
}

// Every way the agent stops other than a detected loss (SIGTERM is Server.Close, then TTL,
// an embedder's own ln.Close) used to unlink whatever sat at the socket path, though Serve
// documents that it leaves a replacement alone: UnixListener unlinks by name on close.
func TestStoppingLeavesAReplacementOfItsSocketAlone(t *testing.T) {
	replace := map[string]func(t *testing.T, sock string){
		"regular file": func(t *testing.T, sock string) {
			if err := os.WriteFile(sock, []byte("mine"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"other socket": func(t *testing.T, sock string) {
			other, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			other.(*net.UnixListener).SetUnlinkOnClose(false) // keep the file for the check below
			t.Cleanup(func() { other.Close() })
		},
	}
	for _, stop := range []string{"Server.Close", "TTL", "Listener.Close"} {
		for rname, mk := range replace {
			t.Run(rname+"/"+stop, func(t *testing.T) {
				_, priv, _ := ed25519.GenerateKey(nil)
				srv, err := NewServer(priv)
				if err != nil {
					t.Fatal(err)
				}
				if stop == "TTL" {
					srv.TTL = 300 * time.Millisecond
				}
				sock := filepath.Join(sockDir(t), "agent.sock")
				ln, err := Listen(sock)
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- srv.Serve(ln) }()
				defer srv.Close()
				// The default check interval (10 s) is far off: this is the window in which
				// the agent has not noticed the replacement yet.
				if err := os.Remove(sock); err != nil {
					t.Fatal(err)
				}
				mk(t, sock)
				switch stop {
				case "Server.Close":
					srv.Close()
				case "Listener.Close":
					ln.Close()
				}
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("Serve did not return")
				}
				if _, err := os.Lstat(sock); err != nil {
					t.Errorf("stopping by %s unlinked the file that replaced the socket: %v", stop, err)
				}
			})
		}
	}
}

// socketLost used to flip SetUnlinkOnClose on a listener an embedder may be closing at the
// same moment (the CLI and Server.Close are ordered by s.mu; a direct ln.Close is not).
// Only -race can fail this one.
func TestSocketLostRacingAnEmbeddersListenerCloseIsRaceFree(t *testing.T) {
	for i := 0; i < 300; i++ {
		_, priv, _ := ed25519.GenerateKey(nil)
		srv, err := NewServer(priv)
		if err != nil {
			t.Fatal(err)
		}
		srv.checkEvery = 50 * time.Microsecond
		sock := filepath.Join(sockDir(t), "agent.sock")
		ln, err := Listen(sock)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- srv.Serve(ln) }()
		os.Remove(sock) // the next check reports a loss...
		time.Sleep(time.Duration(i%7) * 40 * time.Microsecond)
		ln.Close() // ...while the embedder closes the listener itself
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("run %d: Serve did not return", i)
		}
		srv.Close()
	}
}

// An embedder may Listen on a relative path and change directory later. The loss check
// used to Lstat the stored relative path from the new directory, so a healthy agent
// reported its socket "removed or replaced", stopped, and left the socket on disk.
func TestRelativeSocketPathSurvivesAChdir(t *testing.T) {
	dir := sockDir(t)
	t.Chdir(dir)
	_, priv, _ := ed25519.GenerateKey(nil)
	srv, err := NewServer(priv)
	if err != nil {
		t.Fatal(err)
	}
	srv.checkEvery = 10 * time.Millisecond
	ln, err := Listen("rel.sock")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	defer srv.Close()
	t.Chdir(sockDir(t)) // anywhere else
	select {
	case err := <-done:
		t.Fatalf("Serve stopped after a chdir: %v", err)
	case <-time.After(300 * time.Millisecond): // thirty checks
	}
	if _, err := Dial(filepath.Join(dir, "rel.sock")); err != nil {
		t.Fatalf("the agent is not reachable after a chdir: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Serve after Close = %v, want nil", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "rel.sock")); !os.IsNotExist(err) {
		t.Errorf("the socket was not removed on Close: %v", err)
	}
}

// The socket is bound by its absolute path (UnixListener unlinks by the name bound, so a
// relative one would miss after a chdir), hence sun_path's limit applies to the absolute
// form: a relative name that makes it exactly 103 bytes binds, one more is refused with the
// limit named, and no lock file is left behind.
func TestListenLengthLimitAppliesToTheAbsolutePath(t *testing.T) {
	max := len(syscall.RawSockaddrUnix{}.Path) - 1
	dir := sockDir(t)
	t.Chdir(dir)
	if abs, _ := filepath.Abs("x"); len(abs) != len(dir)+2 { // /tmp is a symlink on macOS: Getwd must not resolve it
		t.Fatalf("test setup: Abs(x) = %q for dir %q", abs, dir)
	}
	ln, err := Listen(strings.Repeat("s", max-len(dir)-1))
	if err != nil {
		t.Fatalf("a relative path whose absolute form is exactly %d bytes was refused: %v", max, err)
	}
	ln.Close()
	os.Remove(strings.Repeat("s", max-len(dir)-1) + ".lock")
	_, err = Listen(strings.Repeat("s", max-len(dir)))
	if err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("a relative path whose absolute form is %d bytes: err = %v, want the limit error", max+1, err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*")); len(left) != 0 {
		t.Errorf("rejected path left files behind: %v", left)
	}
}
