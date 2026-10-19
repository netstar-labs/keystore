package agent

import (
	"crypto"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// failSigner makes every signature fail, for the "refused sign" case.
type failSigner struct{ crypto.Signer }

func (failSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("signing refused")
}

// hungUp reads until the server closes the connection. A client that still has unread
// bytes queued when the server closes sees ECONNRESET instead of EOF (Linux); both mean
// the server is done with the connection, which is after its last chance to count the
// request as use.
func hungUp(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, conn); err != nil && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("waiting for the server to hang up: %v", err)
	}
}

// idleProbe reports, once a connection's handler is finished, whether it queued a "this
// was use" touch for watch. watch is frozen inside its first Reset (the fake clock's
// gate), so the question has a stable answer: a sentinel touch is pushed behind whatever
// is queued; watch parks in Reset on whichever touch it consumed first, and the sentinel
// is still waiting in the queue exactly when that first touch was the handler's.
func idleProbe(t *testing.T, r *running, clk *fakeClock) (handlerTouched bool) {
	t.Helper()
	r.srv.mu.Lock()
	touch := r.srv.touch
	r.srv.mu.Unlock()
	select {
	case touch <- struct{}{}: // blocks while the handler's touch is still queued
	case <-time.After(5 * time.Second):
		t.Fatal("touch queue never drained")
	}
	for deadline := time.Now().Add(5 * time.Second); clk.parked.Load() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("watch never reached Reset")
		}
		time.Sleep(time.Millisecond)
	}
	return len(touch) != 0
}

func startProbed(t *testing.T, setup func(*Server)) (*running, *fakeClock) {
	t.Helper()
	clk := newFakeClock()
	clk.gate = make(chan struct{})
	t.Cleanup(func() { close(clk.gate) }) // runs before the server's Close: nothing stays parked
	r := start(t, func(s *Server) {
		s.Idle, s.afterFunc = time.Minute, clk.afterFunc
		if setup != nil {
			setup(s)
		}
	})
	select {
	case <-clk.armed:
	case <-time.After(5 * time.Second):
		t.Fatal("watch never armed its timer")
	}
	return r, clk
}

// A request the agent refuses is not use: otherwise anyone who can reach the socket
// could keep the key in memory for ever with garbage.
func TestIdleNotResetByFailedRequests(t *testing.T) {
	oversize := []byte{OpSign, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(oversize[1:], MaxPayload+1)
	for _, tc := range []struct {
		name  string
		setup func(*Server)
		send  []byte
	}{
		{"wrong uid", func(s *Server) { s.uidOf = func(*net.UnixConn) (int, error) { return os.Getuid() + 1, nil } }, []byte{OpPublic, 0, 0, 0, 0}},
		{"unknown op", nil, []byte{'X', 0, 0, 0, 0}},
		{"oversize frame", nil, oversize},
		{"failed sign", func(s *Server) { s.signer = failSigner{s.signer} }, []byte{OpSign, 0, 0, 0, 1, 'x'}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, clk := startProbed(t, tc.setup)
			conn, err := net.Dial("unix", r.sock)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.Write(tc.send)
			hungUp(t, conn)
			if idleProbe(t, r, clk) {
				t.Fatal("a refused request was counted as use (it queued an idle reset)")
			}
		})
	}
}

// The control for the probe above: it must see a successful request's touch.
func TestIdleProbeSeesASuccessfulRequest(t *testing.T) {
	r, clk := startProbed(t, nil)
	conn, err := net.Dial("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := writeFrame(conn, OpPublic, nil); err != nil {
		t.Fatal(err)
	}
	if st, _, err := readFrame(conn); err != nil || st != StatusOK {
		t.Fatalf("status %d, %v", st, err)
	}
	// The touch is queued after the reply is written: wait for it to be queued or taken.
	r.srv.mu.Lock()
	touch := r.srv.touch
	r.srv.mu.Unlock()
	for deadline := time.Now().Add(5 * time.Second); len(touch) == 0 && clk.parked.Load() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("a successful request queued no touch")
		}
		time.Sleep(time.Millisecond)
	}
	if !idleProbe(t, r, clk) {
		t.Fatal("probe missed the successful request's touch")
	}
}
