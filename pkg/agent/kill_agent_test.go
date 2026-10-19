package agent

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/netstar-labs/keystore/pkg/keystore"
)

// fakeAgent listens on a fresh socket and runs handle for every connection; it stands in
// for a hostile or broken agent at the other end of the client's socket.
func fakeAgent(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	sock := filepath.Join(sockDir(t), "fake.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handle(c)
			}()
		}
	}()
	return sock
}

// scripted answers OpPublic with pub and OpSign with sig, whatever their size.
func scripted(pub, sig []byte) func(net.Conn) {
	return func(c net.Conn) {
		for {
			op, _, err := readFrame(c)
			if err != nil {
				return
			}
			reply := pub
			if op == OpSign {
				reply = sig
			}
			if writeFrame(c, StatusOK, reply) != nil {
				return
			}
		}
	}
}

// expectEOF fails unless the next read on c reports the peer closed the connection.
func expectEOF(t *testing.T, c net.Conn, what string) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("%s: read = %d bytes, %v; want the connection closed (EOF)", what, n, err)
	}
}

// The client trusts nothing the agent says: the public key must be exactly 32 bytes and
// every signature must verify under it, over the very message that was sent.
func TestClientChecksTheAgentsAnswers(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	_, privB, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("the message")
	good := ed25519.Sign(privA, msg)

	for _, n := range []int{0, 31, 33, 64} {
		sock := fakeAgent(t, scripted(make([]byte, n), nil))
		if _, err := Dial(sock); err == nil {
			t.Errorf("Dial accepted a %d-byte public key", n)
		}
	}

	for name, c := range map[string]struct {
		sig []byte
		ok  bool
	}{
		"correct":                {good, true},
		"garbage 64 bytes":       {make([]byte, 64), false},
		"signed by another key":  {ed25519.Sign(privB, msg), false},
		"over another message":   {ed25519.Sign(privA, []byte("other")), false},
		"one byte short":         {good[:63], false},
		"one byte long":          {append(append([]byte(nil), good...), 0), false},
		"empty":                  {nil, false},
		"one flipped bit":        {func() []byte { s := append([]byte(nil), good...); s[10] ^= 1; return s }(), false},
		"correct but with spare": {append(append([]byte(nil), good...), good...), false},
	} {
		sock := fakeAgent(t, scripted(pubA, c.sig))
		cl, err := Dial(sock)
		if err != nil {
			t.Fatalf("%s: Dial: %v", name, err)
		}
		sig, err := cl.Sign(nil, msg, crypto.Hash(0))
		if c.ok && (err != nil || !bytes.Equal(sig, good)) {
			t.Errorf("%s: Sign = %x, %v", name, sig, err)
		}
		if !c.ok && (err == nil || sig != nil) {
			t.Errorf("%s: Sign returned %x, %v; want an error and no signature", name, sig, err)
		}
	}
}

// The oversize check precedes the dial: nothing is connected to for a message the
// protocol cannot carry.
func TestClientRefusesOversizeBeforeDialling(t *testing.T) {
	c := &Client{path: filepath.Join(sockDir(t), "nobody-home.sock"), Timeout: time.Second}
	if _, err := c.Sign(nil, make([]byte, MaxPayload+1), crypto.Hash(0)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Sign(1 MiB + 1) with no agent = %v, want ErrTooLarge (not a dial error)", err)
	}
	if _, err := c.Sign(nil, make([]byte, MaxPayload), crypto.Hash(0)); err == nil || errors.Is(err, ErrTooLarge) {
		t.Fatalf("Sign(1 MiB) with no agent = %v, want the dial error", err)
	}
}

// An agent that accepts and then says nothing must not hang the caller past its Timeout.
func TestClientGivesUpOnASilentAgent(t *testing.T) {
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	sock := fakeAgent(t, func(c net.Conn) {
		readFrame(c)
		<-hold
	})
	cl := &Client{path: sock, Timeout: 200 * time.Millisecond}
	res := make(chan error, 1)
	go func() { _, err := cl.roundTrip(OpPublic, nil); res <- err }()
	select {
	case err := <-res:
		if err == nil {
			t.Fatal("roundTrip succeeded against a silent agent")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client is still waiting on a silent agent long after its Timeout")
	}
}

func TestDialUsesTheDocumentedTimeout(t *testing.T) {
	r := start(t, nil)
	c, err := Dial(r.sock)
	if err != nil {
		t.Fatal(err)
	}
	if DefaultTimeout != 5*time.Second || c.Timeout != 5*time.Second {
		t.Fatalf("DefaultTimeout = %v, client Timeout = %v; documented 5 s", DefaultTimeout, c.Timeout)
	}
}

// The frame limit is exactly 1 MiB in both directions (docs/agent-protocol.md); literals,
// so a drifting MaxPayload constant cannot move the test with it.
func TestFrameLimitIsExactly1MiB(t *testing.T) {
	if MaxPayload != 1048576 {
		t.Fatalf("MaxPayload = %d, documented 1048576", MaxPayload)
	}
	var buf bytes.Buffer
	if err := writeFrame(&buf, OpSign, make([]byte, 1048576)); err != nil {
		t.Fatalf("writeFrame(1 MiB): %v", err)
	}
	op, p, err := readFrame(&buf)
	if err != nil || op != OpSign || len(p) != 1048576 {
		t.Fatalf("readFrame(1 MiB) = %c, %d bytes, %v", op, len(p), err)
	}
	buf.Reset()
	if err := writeFrame(&buf, OpSign, make([]byte, 1048577)); !errors.Is(err, ErrTooLarge) || buf.Len() != 0 {
		t.Fatalf("writeFrame(1 MiB + 1) = %v after writing %d bytes; want ErrTooLarge and nothing written", err, buf.Len())
	}
	hdr := []byte{OpSign, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(hdr[1:], 1048577)
	if _, _, err := readFrame(bytes.NewReader(hdr)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("readFrame(len 1 MiB + 1) = %v, want ErrTooLarge", err)
	}
	binary.BigEndian.PutUint32(hdr[1:], 0xFFFFFFFF)
	if _, _, err := readFrame(bytes.NewReader(hdr)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("readFrame(len 4 GiB) = %v, want ErrTooLarge", err)
	}
	if op, p, err := readFrame(bytes.NewReader([]byte{OpPublic, 0, 0, 0, 0})); err != nil || op != OpPublic || len(p) != 0 {
		t.Fatalf("empty frame: %c %d %v", op, len(p), err)
	}
}

// After rejecting a request the agent closes the connection; it does not keep serving it
// and certainly does not follow an error with an OK.
func TestRejectedRequestsEndTheConnection(t *testing.T) {
	r := start(t, nil)
	for name, send := range map[string]func(net.Conn){
		"unknown operation": func(c net.Conn) { writeFrame(c, 'X', nil) },
		"oversize frame": func(c net.Conn) {
			hdr := []byte{OpSign, 0, 0, 0, 0}
			binary.BigEndian.PutUint32(hdr[1:], MaxPayload+1)
			c.Write(hdr)
		},
	} {
		c, err := net.Dial("unix", r.sock)
		if err != nil {
			t.Fatal(err)
		}
		send(c)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if st, _, err := readFrame(c); err != nil || st != StatusErr {
			t.Fatalf("%s: reply status %d, %v; want StatusErr", name, st, err)
		}
		expectEOF(t, c, name+": after the error reply")
		c.Close()
	}
}

type failingSigner struct{ ed25519.PrivateKey }

func (failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("hardware on fire")
}

// A signing failure is reported to the client (without the underlying text) and ends the
// connection.
func TestSignFailureIsReported(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv, err := NewServer(failingSigner{priv})
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(sockDir(t), "agent.sock")
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	writeFrame(c, OpSign, []byte("m"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	st, p, err := readFrame(c)
	if err != nil || st != StatusErr || string(p) != "sign failed" {
		t.Fatalf("reply = %d %q, %v; want StatusErr \"sign failed\"", st, p, err)
	}
	expectEOF(t, c, "after a sign failure")
}

// IOTimeout bounds how long a connection may sit silent or half-sent: slow or stuck
// clients cannot hold goroutines and descriptors forever.
func TestIOTimeoutDropsStuckClients(t *testing.T) {
	r := start(t, func(s *Server) { s.IOTimeout = 150 * time.Millisecond })
	silent, err := net.Dial("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	half, err := net.Dial("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer half.Close()
	half.Write([]byte{OpSign, 0, 0}) // two bytes of a five-byte header
	expectEOF(t, silent, "silent client")
	expectEOF(t, half, "half-sent header")
	if _, err := Dial(r.sock); err != nil {
		t.Fatalf("agent unusable after dropping stuck clients: %v", err)
	}
}

// Finished connections are forgotten: the tracking set is bounded by the open ones.
func TestFinishedConnectionsAreUntracked(t *testing.T) {
	r := start(t, nil)
	for i := 0; i < 20; i++ {
		c, err := net.Dial("unix", r.sock)
		if err != nil {
			t.Fatal(err)
		}
		writeFrame(c, OpPublic, nil)
		readFrame(c)
		c.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		r.srv.mu.Lock()
		n := len(r.srv.conns)
		r.srv.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d finished connections still tracked", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A peer whose uid lookup reports an error is refused even when the uid it also returned
// happens to be ours: an error means the uid is not established.
func TestPeerLookupErrorIsRefusedEvenWithOurUID(t *testing.T) {
	r := start(t, func(s *Server) {
		s.uidOf = func(*net.UnixConn) (int, error) { return os.Getuid(), errors.New("half an answer") }
	})
	if _, err := Dial(r.sock); err == nil {
		t.Fatal("agent served a peer whose credentials lookup failed")
	}
}

// If the accept loop meets a connection while the server is already stopping, that
// connection is closed, not served: the key must not answer after Close.
func TestConnectionAcceptedDuringShutdownIsClosed(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv, _ := NewServer(priv)
	dir := sockDir(t)
	ln, err := Listen(filepath.Join(dir, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	side, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "side.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer side.Close()
	client, err := net.Dial("unix", filepath.Join(dir, "side.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	calls := 0
	srv.accept = func(*Listener) (*net.UnixConn, error) {
		calls++
		if calls == 1 {
			srv.Close() // shutdown begins while this accept is in flight
			return side.AcceptUnix()
		}
		return nil, net.ErrClosed
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	writeFrame(client, OpPublic, nil)
	expectEOF(t, client, "connection accepted during shutdown")
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return")
	}
}

type gateSigner struct {
	ed25519.PrivateKey
	entered chan struct{}
	release chan struct{}
}

func (g gateSigner) Sign(r io.Reader, m []byte, o crypto.SignerOpts) ([]byte, error) {
	close(g.entered)
	<-g.release
	return g.PrivateKey.Sign(r, m, o)
}

// Serve does not return while a request is still being processed: once it has returned,
// no goroutine of the server touches the key any more.
func TestServeWaitsForInFlightRequests(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	g := gateSigner{priv, make(chan struct{}), make(chan struct{})}
	srv, _ := NewServer(g)
	ln, err := Listen(filepath.Join(sockDir(t), "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	c, err := net.Dial("unix", filepath.Join(filepath.Dir(ln.Addr().String()), "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	writeFrame(c, OpSign, []byte("m"))
	select {
	case <-g.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("request never reached the signer")
	}
	srv.Close()
	select {
	case <-done:
		t.Fatal("Serve returned while a request was still inside the signer")
	case <-time.After(300 * time.Millisecond):
	}
	close(g.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return once the request finished")
	}
}

// Close while the accept loop is running (proved by a round trip first, so Serve cannot
// have taken its Close-before-Serve exit) ends Serve with nil and removes the socket;
// the closed listener is the normal way out, not an error to report.
func TestCloseWhileServingReturnsNil(t *testing.T) {
	r := start(t, nil)
	c, err := Dial(r.sock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sign(nil, []byte("m"), crypto.Hash(0)); err != nil {
		t.Fatal(err)
	}
	if err := r.srv.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	select {
	case err := <-r.done:
		if err != nil {
			t.Fatalf("Serve after Close = %v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
	if _, err := os.Lstat(r.sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket left behind: %v", err)
	}
	if err := r.srv.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil", err)
	}
}

// ENFILE (system-wide descriptor exhaustion) is as transient as EMFILE.
func TestAcceptENFILEIsRetried(t *testing.T) {
	fail := make(chan struct{}, 1)
	fail <- struct{}{}
	r := start(t, func(s *Server) {
		s.accept = func(ln *Listener) (*net.UnixConn, error) {
			select {
			case <-fail:
				return nil, &net.OpError{Op: "accept", Err: os.NewSyscallError("accept", syscall.ENFILE)}
			default:
				return ln.AcceptUnix()
			}
		}
	})
	c, err := Dial(r.sock)
	if err != nil {
		t.Fatalf("agent did not survive ENFILE on accept: %v", err)
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

// Retrying after EMFILE backs off instead of spinning: a process that is out of
// descriptors must not also burn a core asking for another one.
func TestAcceptRetryBacksOff(t *testing.T) {
	var calls atomic.Int64
	began := time.Now()
	r := start(t, func(s *Server) {
		s.accept = func(ln *Listener) (*net.UnixConn, error) {
			calls.Add(1)
			if time.Since(began) < 400*time.Millisecond {
				return nil, &net.OpError{Op: "accept", Err: os.NewSyscallError("accept", syscall.EMFILE)}
			}
			return ln.AcceptUnix()
		}
	})
	time.Sleep(450 * time.Millisecond)
	if n := calls.Load(); n > 40 {
		t.Fatalf("%d accept attempts in 400 ms of EMFILE: the retry loop is spinning", n)
	}
	if _, err := Dial(r.sock); err != nil {
		t.Fatalf("agent unusable once descriptors came back: %v", err)
	}
}

// A live socket that nothing holds the path lock for (an agent from before the lock
// existed, or any other server) is still detected by dialling it, and left alone.
func TestListenRefusesALiveSocketWithoutALock(t *testing.T) {
	sock := filepath.Join(sockDir(t), "other.sock")
	other, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	go func() {
		for {
			c, err := other.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if _, err := Listen(sock); !errors.Is(err, ErrInUse) {
		t.Fatalf("Listen over a live foreign socket = %v, want ErrInUse", err)
	}
	if c, err := net.Dial("unix", sock); err != nil {
		t.Fatalf("the live socket was disturbed: %v", err)
	} else {
		c.Close()
	}
}

// The socket directory must be closed to group and others in every bit, not just some.
func TestSocketDirEveryGroupAndOtherBitIsRefused(t *testing.T) {
	dir := sockDir(t)
	for _, mode := range []os.FileMode{0o710, 0o720, 0o740, 0o701, 0o702, 0o704, 0o750, 0o705, 0o770, 0o707, 0o777} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if ln, err := Listen(filepath.Join(dir, "a.sock")); err == nil {
			ln.Close()
			t.Errorf("Listen accepted a directory of mode %04o", mode)
		}
	}
	os.Chmod(dir, 0o700)
	ln, err := Listen(filepath.Join(dir, "a.sock"))
	if err != nil {
		t.Fatalf("a 0700 directory was refused: %v", err)
	}
	ln.Close()
}

// A directory owned by someone else is refused for that reason (its owner could swap the
// socket under us), whatever its mode. "/" is root's on every platform this runs on.
func TestSocketDirMustBeOwnedByTheCaller(t *testing.T) {
	st, err := os.Stat("/")
	if err != nil {
		t.Fatal(err)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || int(sys.Uid) == os.Getuid() {
		t.Skip("/ is owned by the current user (running as root?): no foreign-owned directory to test with")
	}
	ln, err := Listen("/keystore-agent-test.sock")
	if err == nil {
		ln.Close()
		t.Fatal("Listen succeeded in a directory owned by someone else")
	}
	if !strings.Contains(err.Error(), "not owned by the current user") {
		t.Fatalf("Listen in / = %v, want the ownership refusal", err)
	}
	if _, err := os.Lstat("/keystore-agent-test.sock.lock"); err == nil {
		os.Remove("/keystore-agent-test.sock.lock")
		t.Fatal("a refused Listen left a lock file in the foreign directory")
	}
}

// The path lock file is never followed through a symlink and is created owner-only
// whatever the process umask.
func TestListenLockFileIsNotFollowedAndIsOwnerOnly(t *testing.T) {
	dir := sockDir(t)
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "a.sock")
	if err := os.Symlink(victim, sock+".lock"); err != nil {
		t.Fatal(err)
	}
	if ln, err := Listen(sock); err == nil {
		ln.Close()
		t.Fatal("Listen followed a symlinked lock file")
	}
	if b, _ := os.ReadFile(victim); string(b) != "precious" {
		t.Fatalf("symlink target modified: %q", b)
	}
	os.Remove(sock + ".lock")

	old := syscall.Umask(0)
	defer syscall.Umask(old)
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	st, err := os.Stat(sock + ".lock")
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("lock file: %v, %v; want mode 0600 under umask 0", st, err)
	}
}

// The passphrase the caller supplied is wiped once the key is unlocked.
func TestResolveSignerWipesThePassphrase(t *testing.T) {
	ring := filepath.Join(t.TempDir(), "r.ks")
	k, err := keystore.Create(ring)
	if err != nil {
		t.Fatal(err)
	}
	pw := []byte("resolve wipe test passphrase")
	if _, err := k.Add("a", pw); err != nil {
		t.Fatal(err)
	}
	var handed []byte
	_, err = ResolveSigner("", ring, "a", func() ([]byte, error) {
		handed = append([]byte(nil), pw...)
		return handed, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(handed, make([]byte, len(handed))) {
		t.Fatalf("passphrase buffer still holds %q after ResolveSigner", handed)
	}
}

// ResolveSigner honours the key id.
func TestResolveSignerHonoursTheID(t *testing.T) {
	ring := filepath.Join(t.TempDir(), "r.ks")
	k, _ := keystore.Create(ring)
	pw := []byte("resolve id test passphrase")
	k.Add("a", pw)
	pubB, _ := k.Add("b", pw)
	s, err := ResolveSigner("", ring, "b", func() ([]byte, error) { return append([]byte(nil), pw...), nil })
	if err != nil || !s.Public().(ed25519.PublicKey).Equal(pubB) {
		t.Fatalf("ResolveSigner(id b) = %v, %v", s, err)
	}
}
