package agent

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock replaces the server's timers (Server.afterFunc) so expiry tests advance time
// by hand instead of sleeping. Timers run their callbacks inside Advance, on the test's
// goroutine; the channels below are the only synchronisation the tests need with the
// server's watch goroutine.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Duration
	timers  []*fakeTimer
	fired   int
	armed   chan struct{} // one send per afterFunc call
	resets  chan struct{} // one send per Reset, i.e. per request the server counted as use
	stopped chan struct{} // one send per Stop (watch stops its timers just after Serve returns)
	gate    chan struct{} // if non-nil (set before the server starts), Reset blocks on it until closed
	parked  atomic.Int32  // Reset calls begun
}

type fakeTimer struct {
	c      *fakeClock
	when   time.Duration
	f      func()
	active bool
}

func newFakeClock() *fakeClock {
	return &fakeClock{armed: make(chan struct{}, 8), resets: make(chan struct{}, 64), stopped: make(chan struct{}, 8)}
}

func (c *fakeClock) afterFunc(d time.Duration, f func()) timer {
	c.mu.Lock()
	t := &fakeTimer{c: c, when: c.now + d, f: f, active: true}
	c.timers = append(c.timers, t)
	c.mu.Unlock()
	c.armed <- struct{}{}
	return t
}

func (t *fakeTimer) Reset(d time.Duration) bool {
	t.c.parked.Add(1)
	if g := t.c.gate; g != nil {
		<-g // lets a test freeze watch inside Reset
	}
	t.c.mu.Lock()
	was := t.active
	t.active, t.when = true, t.c.now+d
	t.c.mu.Unlock()
	t.c.resets <- struct{}{}
	return was
}

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := t.active
	t.active = false
	t.c.stopped <- struct{}{}
	return was
}

// Advance moves time forward and runs every timer that has come due, in creation order.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now += d
	var due []*fakeTimer
	for _, t := range c.timers {
		if t.active && t.when <= c.now {
			t.active = false
			due = append(due, t)
		}
	}
	c.fired += len(due)
	c.mu.Unlock()
	for _, t := range due {
		t.f()
	}
}

func (c *fakeClock) Fired() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fired
}

// startFake starts a server on a fake clock and waits until its timers are armed, so a
// later Advance cannot run before watch has set them.
func startFake(t *testing.T, ttl, idle time.Duration) (*running, *fakeClock) {
	t.Helper()
	clk := newFakeClock()
	r := start(t, func(s *Server) { s.TTL, s.Idle, s.afterFunc = ttl, idle, clk.afterFunc })
	for n := 0; n < btoi(ttl > 0)+btoi(idle > 0); n++ {
		select {
		case <-clk.armed:
		case <-time.After(5 * time.Second):
			t.Fatal("watch never armed its timers")
		}
	}
	return r, clk
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// served waits for Serve to return; the 5 s bound only turns a hang into a failure.
func served(t *testing.T, r *running) error {
	t.Helper()
	select {
	case err := <-r.done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
		return nil
	}
}

func wantExpired(t *testing.T, r *running) {
	t.Helper()
	if err := served(t, r); !errors.Is(err, ErrExpired) {
		t.Fatalf("Serve = %v, want ErrExpired", err)
	}
}

func wantNotFired(t *testing.T, clk *fakeClock, r *running) {
	t.Helper()
	if n := clk.Fired(); n != 0 {
		t.Fatalf("%d timer(s) fired early", n)
	}
	select {
	case err := <-r.done:
		t.Fatalf("Serve returned early: %v", err)
	default:
	}
}

// sign makes exactly one successful request (Dial would make two: it fetches the key first).
func sign(t *testing.T, r *running) {
	t.Helper()
	conn, err := net.Dial("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := writeFrame(conn, OpSign, []byte("use")); err != nil {
		t.Fatal(err)
	}
	if st, _, err := readFrame(conn); err != nil || st != StatusOK {
		t.Fatalf("sign: status %d, %v", st, err)
	}
}

func waitReset(t *testing.T, clk *fakeClock) {
	t.Helper()
	select {
	case <-clk.resets:
	case <-time.After(5 * time.Second):
		t.Fatal("a successful request did not reset the idle timer")
	}
}

func TestTTLExpiresExactlyAtTTL(t *testing.T) {
	const ttl = time.Hour
	r, clk := startFake(t, ttl, 0)
	clk.Advance(ttl - time.Nanosecond)
	wantNotFired(t, clk, r)
	sign(t, r) // still serving one nanosecond before
	clk.Advance(time.Nanosecond)
	wantExpired(t, r)
	if _, err := os.Lstat(r.sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("socket left behind after TTL")
	}
}

func TestIdleExpiresExactlyAtIdle(t *testing.T) {
	const idle = time.Minute
	r, clk := startFake(t, 0, idle)
	clk.Advance(idle - time.Nanosecond)
	wantNotFired(t, clk, r)
	clk.Advance(time.Nanosecond)
	wantExpired(t, r)
}

func TestIdleResetBySuccessfulRequest(t *testing.T) {
	const idle = time.Minute
	r, clk := startFake(t, 0, idle)
	for i := 0; i < 3; i++ { // each use buys a whole new window; without Reset the second advance would fire
		clk.Advance(idle - time.Nanosecond)
		wantNotFired(t, clk, r)
		sign(t, r)
		waitReset(t, clk)
	}
	clk.Advance(idle - time.Nanosecond)
	wantNotFired(t, clk, r)
	clk.Advance(time.Nanosecond)
	wantExpired(t, r)
}

// A connection that keeps being used must not extend the TTL (a busy client would keep
// the key in memory for ever); expiry closes it.
func TestTTLNotExtendedByPersistentConnectionFake(t *testing.T) {
	const ttl = time.Hour
	r, clk := startFake(t, ttl, 0)
	conn, err := net.Dial("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 3; i++ {
		clk.Advance(ttl/4 - time.Nanosecond)
		if err := writeFrame(conn, OpSign, []byte("keepalive")); err != nil {
			t.Fatal(err)
		}
		if st, _, err := readFrame(conn); err != nil || st != StatusOK {
			t.Fatalf("request %d: status %d, %v", i, st, err)
		}
		clk.Advance(time.Nanosecond)
	}
	wantNotFired(t, clk, r)
	clk.Advance(ttl / 4)
	wantExpired(t, r)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatalf("open connection not closed by expiry: %v", err)
	}
}

// TTL and Idle reaching their deadline at the same instant both fire; Serve still
// reports ErrExpired once and Close afterwards is harmless.
func TestTTLAndIdleExpireTogether(t *testing.T) {
	const d = time.Minute
	r, clk := startFake(t, d, d)
	clk.Advance(d)
	wantExpired(t, r)
	if n := clk.Fired(); n != 2 {
		t.Fatalf("%d timers fired, want 2", n)
	}
	if err := r.srv.Close(); err != nil {
		t.Fatalf("Close after expiry = %v", err)
	}
	select {
	case err := <-r.done:
		t.Fatalf("Serve returned a second time: %v", err)
	default:
	}
}

// Close racing expiry: once the deadline has fired, a Close from elsewhere (SIGTERM
// arriving while connections drain) must not turn the reason into a clean stop.
func TestCloseAfterExpiryKeepsErrExpired(t *testing.T) {
	r, clk := startFake(t, time.Minute, 0)
	conn, err := net.Dial("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	clk.Advance(time.Minute)
	for i := 0; i < 3; i++ {
		if err := r.srv.Close(); err != nil {
			t.Fatalf("Close #%d = %v", i, err)
		}
	}
	wantExpired(t, r)
}

// The other order: Close first is a clean stop, and the stopped timers cannot fire later.
func TestCloseBeforeExpiryIsCleanAndDisarmsTimers(t *testing.T) {
	r, clk := startFake(t, time.Minute, time.Minute)
	if err := r.srv.Close(); err != nil {
		t.Fatal(err)
	}
	if err := served(t, r); err != nil {
		t.Fatalf("Serve after Close = %v, want nil", err)
	}
	// Serve returns before watch has run its deferred Stops; wait for both, as time
	// passing in that gap would (harmlessly) fire expire on a server that is already down.
	for i := 0; i < 2; i++ {
		select {
		case <-clk.stopped:
		case <-time.After(5 * time.Second):
			t.Fatal("watch did not stop its timers after Serve returned")
		}
	}
	clk.Advance(time.Hour)
	if n := clk.Fired(); n != 0 {
		t.Fatalf("%d timer(s) fired after Close", n)
	}
}

func TestNegativeLifetimeArmsNoTimer(t *testing.T) {
	for _, tc := range []struct{ ttl, idle time.Duration }{{-1, 0}, {0, -1}, {time.Hour, -time.Nanosecond}} {
		clk := newFakeClock()
		r := start(t, func(s *Server) { s.TTL, s.Idle, s.afterFunc = tc.ttl, tc.idle, clk.afterFunc })
		if err := served(t, r); !errors.Is(err, ErrNegativeLifetime) {
			t.Fatalf("ttl=%v idle=%v: Serve = %v, want ErrNegativeLifetime", tc.ttl, tc.idle, err)
		}
		if len(clk.armed) != 0 {
			t.Fatalf("ttl=%v idle=%v: a timer was armed before refusing", tc.ttl, tc.idle)
		}
	}
}

func TestZeroLifetimeArmsNoTimer(t *testing.T) {
	clk := newFakeClock()
	r := start(t, func(s *Server) { s.afterFunc = clk.afterFunc })
	sign(t, r)
	clk.Advance(1000 * time.Hour)
	if len(clk.armed) != 0 || clk.Fired() != 0 {
		t.Fatal("TTL=Idle=0 must mean no timers")
	}
}
