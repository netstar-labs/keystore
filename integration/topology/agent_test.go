//go:build topology

package topology

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/netstar-labs/keystore/pkg/agent"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// aproc is a running keystore-agent process.
type aproc struct {
	cmd      *exec.Cmd
	log      *syncBuf
	done     chan struct{}
	code     int
	launched time.Time
	ready    time.Time // first moment a dial to the socket succeeded
	exited   time.Time
}

func startAgentRaw(ring, sock, home, pw string, flags ...string) *aproc {
	args := append([]string{"-keystore", ring, "-sock", sock}, flags...)
	cmd := exec.Command(bin("keystore-agent"), args...)
	cmd.Env = append(cleanEnv(home), "KEYSTORE_PASSPHRASE="+pw)
	p := &aproc{cmd: cmd, log: &syncBuf{}, done: make(chan struct{}), launched: time.Now()}
	cmd.Stderr, cmd.Stdout = p.log, p.log
	if err := cmd.Start(); err != nil {
		p.code = -2
		p.exited = time.Now()
		close(p.done)
		return p
	}
	go func() {
		cmd.Wait()
		p.exited = time.Now()
		p.code = cmd.ProcessState.ExitCode()
		close(p.done)
	}()
	return p
}

// waitReady polls until a connection to sock is accepted, or the process exits.
func (p *aproc) waitReady(sock string) bool {
	dl := time.Now().Add(20 * time.Second)
	for time.Now().Before(dl) {
		select {
		case <-p.done:
			return false
		default:
		}
		if c, err := net.DialTimeout("unix", sock, time.Second); err == nil {
			c.Close()
			p.ready = time.Now()
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func (p *aproc) exited1() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *aproc) wait(t *testing.T, d time.Duration) bool {
	t.Helper()
	select {
	case <-p.done:
		return true
	case <-time.After(d):
		return false
	}
}

type agentEnv struct {
	dir, ring, sock, home string
	pub                   ed25519.PublicKey
}

// newAgentEnv makes a ring with a signing key "k1" and a private socket directory.
func newAgentEnv(t *testing.T) *agentEnv {
	t.Helper()
	d := workDir(t)
	e := &agentEnv{dir: d, ring: filepath.Join(d, "r.ks"), home: filepath.Join(d, "h")}
	os.Mkdir(e.home, 0o700)
	sd := filepath.Join(d, "s")
	os.Mkdir(sd, 0o700)
	e.sock = filepath.Join(sd, "a.sock")
	if r := ks(e.home, pass(0), "", "keygen", "-keystore", e.ring, "-id", "k1"); !r.ok() {
		t.Fatalf("keygen: %s", r.stderr)
	}
	c := ks(e.home, "", "", "export-pub", "-keystore", e.ring, "-id", "k1")
	pub, err := parsePub(c.stdout)
	if err != nil {
		t.Fatal(err)
	}
	e.pub = pub
	return e
}

func (e *agentEnv) start(t *testing.T, flags ...string) *aproc {
	t.Helper()
	p := startAgentRaw(e.ring, e.sock, e.home, pass(0), flags...)
	if !p.waitReady(e.sock) {
		t.Fatalf("agent did not come up: code=%d log=%s", p.code, p.log.String())
	}
	return p
}

// signOnce dials, signs a unique message and returns the client-verified signature's validity.
func signOnce(sock string, msg []byte, want ed25519.PublicKey) error {
	c, err := agent.Dial(sock)
	if err != nil {
		return err
	}
	if !bytes.Equal(c.Public().(ed25519.PublicKey), want) {
		return errors.New("VIOLATION: agent serves a different public key")
	}
	sig, err := c.Sign(nil, msg, nil)
	if err != nil {
		return err
	}
	if !ed25519.Verify(want, msg, sig) {
		return errors.New("VIOLATION: signature does not verify")
	}
	return nil
}

func isViolation(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "VIOLATION") || isBadSig(err))
}
func isBadSig(err error) bool {
	return err != nil && strings.Contains(err.Error(), "invalid signature")
}

// hammer runs n client goroutines signing in a loop until stop is closed.
type hammer struct {
	ok, bad, viol atomic.Int64
	lastOK        atomic.Int64 // unix nanos of the most recent success
	wg            sync.WaitGroup
	stop          chan struct{}
}

func startHammer(sock string, pub ed25519.PublicKey, n int) *hammer {
	h := &hammer{stop: make(chan struct{})}
	for i := 0; i < n; i++ {
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			for seq := 0; ; seq++ {
				select {
				case <-h.stop:
					return
				default:
				}
				err := signOnce(sock, []byte(fmt.Sprintf("msg-%d-%d-%d", i, seq, time.Now().UnixNano())), pub)
				switch {
				case err == nil:
					h.ok.Add(1)
					h.lastOK.Store(time.Now().UnixNano())
				case isViolation(err):
					h.viol.Add(1)
				default:
					h.bad.Add(1)
					time.Sleep(2 * time.Millisecond)
				}
			}
		}()
	}
	return h
}

func (h *hammer) finish() { close(h.stop); h.wg.Wait() }

// TestAgentHammerRestart: many concurrent clients, then SIGTERM under load, then a
// replacement agent on the same path while the clients keep going.
func TestAgentHammerRestart(t *testing.T) {
	need(t)
	e := newAgentEnv(t)
	clients := envInt("TOPO_CLIENTS", 48)
	a := e.start(t)
	h := startHammer(e.sock, e.pub, clients)
	time.Sleep(3 * time.Second)
	okBefore := h.ok.Load()
	a.cmd.Process.Signal(syscall.SIGTERM)
	if !a.wait(t, 5*time.Second) {
		t.Fatalf("agent did not stop on SIGTERM under load; log=%s", a.log.String())
	}
	if a.code != 0 {
		t.Errorf("SIGTERM exit code %d, want 0; log=%s", a.code, a.log.String())
	}
	if _, err := os.Lstat(e.sock); err == nil {
		t.Errorf("socket still present after SIGTERM")
	}
	// absence: with the agent gone, no signature may be obtained.
	time.Sleep(200 * time.Millisecond)
	downSince := time.Now()
	time.Sleep(700 * time.Millisecond)
	if last := time.Unix(0, h.lastOK.Load()); last.After(a.exited) {
		t.Errorf("a signature succeeded %v after the agent exited", last.Sub(a.exited))
	}
	if err := signOnce(e.sock, []byte("x"), e.pub); err == nil {
		t.Errorf("sign succeeded with no agent running")
	}
	okDown := h.ok.Load()
	// restart on the same path under load
	b := e.start(t)
	time.Sleep(2 * time.Second)
	okAfter := h.ok.Load()
	h.finish()
	b.cmd.Process.Signal(syscall.SIGTERM)
	b.wait(t, 5*time.Second)
	if h.viol.Load() != 0 {
		t.Errorf("%d client-visible violations (bad signature / wrong key)", h.viol.Load())
	}
	if okAfter <= okDown {
		t.Errorf("clients did not recover after the restart (%d -> %d)", okDown, okAfter)
	}
	if okBefore == 0 {
		t.Errorf("no successful signatures before SIGTERM")
	}
	t.Logf("clients=%d ok-before-SIGTERM=%d ok-after-restart=%d client-errors=%d down-window=%v", clients, okBefore, okAfter-okDown, h.bad.Load(), time.Since(downSince).Round(time.Millisecond))
	record("agent-hammer-restart", map[string]any{"clients": clients, "ok_before": okBefore, "ok_after_restart": okAfter - okDown, "client_errors": h.bad.Load(), "violations": h.viol.Load()})
}

// rawConn opens a connection and performs one P exchange, then leaves it idle.
func rawConn(sock string) (net.Conn, error) {
	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return nil, err
	}
	if _, err := c.Write([]byte{'P', 0, 0, 0, 0}); err != nil {
		c.Close()
		return nil, err
	}
	hdr := make([]byte, 5+32)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, hdr); err != nil {
		c.Close()
		return nil, err
	}
	c.SetReadDeadline(time.Time{})
	return c, nil
}

// TestAgentTTL: the key must not outlive the TTL, observed from outside: a client that
// signed successfully up to the deadline, connections held open across it, and a dial
// after it. (F1 regression at scale.)
func TestAgentTTL(t *testing.T) {
	need(t)
	rounds := envInt("TOPO_TTL_ROUNDS", 3)
	ttl := 3 * time.Second
	const slack = 300 * time.Millisecond
	var worstLast, worstExit time.Duration = -time.Hour, -time.Hour
	for r := 0; r < rounds; r++ {
		e := newAgentEnv(t)
		a := e.start(t, "-ttl", ttl.String(), "-idle", "0")
		deadline := a.ready.Add(ttl) // Serve began before the socket was dialable, so the key dies by here
		var held []net.Conn
		for i := 0; i < 8; i++ {
			c, err := rawConn(e.sock)
			if err != nil {
				t.Fatalf("round %d held conn %d: %v", r, i, err)
			}
			held = append(held, c)
		}
		h := startHammer(e.sock, e.pub, 16)
		// every held connection must see EOF at about the deadline, not later
		var wg sync.WaitGroup
		eofAt := make([]time.Time, len(held))
		for i, c := range held {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c.SetReadDeadline(time.Now().Add(ttl + 4*time.Second))
				buf := make([]byte, 1)
				_, err := c.Read(buf)
				if err != nil {
					eofAt[i] = time.Now()
				}
			}()
		}
		if !a.wait(t, ttl+4*time.Second) {
			t.Fatalf("round %d: agent still alive %v past its ttl", r, 4*time.Second)
		}
		time.Sleep(300 * time.Millisecond)
		h.finish()
		wg.Wait()
		if a.code != 0 {
			t.Errorf("round %d: exit code %d, want 0 on ttl expiry; log=%s", r, a.code, a.log.String())
		}
		last := time.Unix(0, h.lastOK.Load())
		if d := last.Sub(deadline); d > slack {
			t.Errorf("round %d: a signature succeeded %v after the ttl deadline: the key outlived its TTL", r, d)
		} else {
			worstLast = max(worstLast, d)
		}
		if d := a.exited.Sub(deadline); d > time.Second {
			t.Errorf("round %d: agent exited %v after the deadline", r, d)
		} else {
			worstExit = max(worstExit, d)
		}
		for i, ts := range eofAt {
			if ts.IsZero() {
				t.Errorf("round %d: held connection %d never saw EOF", r, i)
			} else if d := ts.Sub(deadline); d > slack+500*time.Millisecond {
				t.Errorf("round %d: held connection %d saw EOF %v after the deadline", r, i, d)
			}
		}
		if err := signOnce(e.sock, []byte("late"), e.pub); err == nil {
			t.Errorf("round %d: sign succeeded after expiry", r)
		}
		if _, err := os.Lstat(e.sock); err == nil {
			t.Errorf("round %d: socket survives expiry", r)
		}
		if h.viol.Load() != 0 {
			t.Errorf("round %d: %d violations", r, h.viol.Load())
		}
	}
	t.Logf("rounds=%d ttl=%v; worst last-successful-sign minus deadline=%v; worst exit minus deadline=%v (negative = before the deadline)", rounds, ttl, worstLast.Round(time.Millisecond), worstExit.Round(time.Millisecond))
	record("agent-ttl", map[string]any{"rounds": rounds, "ttl_s": ttl.Seconds(), "worst_last_sign_vs_deadline_ms": worstLast.Milliseconds(), "worst_exit_vs_deadline_ms": worstExit.Milliseconds()})
}

// TestAgentIdle: idle expiry runs from the last successful request, is pushed out by
// traffic, and is not held off by a connection that stays open and silent.
func TestAgentIdle(t *testing.T) {
	need(t)
	e := newAgentEnv(t)
	idle := 2 * time.Second
	a := e.start(t, "-ttl", "0", "-idle", idle.String())
	hc, err := rawConn(e.sock) // a live but silent connection (this P exchange counts as the first request)
	if err != nil {
		t.Fatal(err)
	}
	defer hc.Close()
	var last time.Time
	for i := 0; i < 6; i++ { // 6 x 700ms = 4.2s of traffic, longer than idle
		if err := signOnce(e.sock, []byte(fmt.Sprintf("m%d", i)), e.pub); err != nil {
			t.Fatalf("sign %d during traffic: %v (agent log: %s)", i, err, a.log.String())
		}
		last = time.Now()
		time.Sleep(700 * time.Millisecond)
	}
	if a.exited1() {
		t.Fatalf("agent expired while traffic kept resetting idle: %s", a.log.String())
	}
	if !a.wait(t, idle+3*time.Second) {
		t.Fatalf("agent never expired after traffic stopped")
	}
	d := a.exited.Sub(last)
	if d < idle-200*time.Millisecond || d > idle+1500*time.Millisecond {
		t.Errorf("idle expiry %v after the last request; want about %v", d, idle)
	}
	if a.code != 0 {
		t.Errorf("exit code %d, want 0", a.code)
	}
	hc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := hc.Read(make([]byte, 1)); err == nil {
		t.Errorf("held silent connection did not see EOF at expiry")
	}
	if err := signOnce(e.sock, []byte("late"), e.pub); err == nil {
		t.Errorf("sign succeeded after idle expiry")
	}
	t.Logf("idle=%v expiry-after-last-request=%v", idle, d.Round(time.Millisecond))
	record("agent-idle", map[string]any{"idle_s": idle.Seconds(), "expiry_after_last_ms": d.Milliseconds()})
}

// TestAgentRaceStart: many agents started at the same instant on one socket path; exactly
// one may win, the rest must refuse, and the winner's socket must be untouched.
func TestAgentRaceStart(t *testing.T) {
	need(t)
	rounds := envInt("TOPO_RACE_ROUNDS", 5)
	racers := envInt("TOPO_RACERS", 10)
	winners := map[int]int{}
	for r := 0; r < rounds; r++ {
		e := newAgentEnv(t)
		procs := make([]*aproc, racers)
		var wg sync.WaitGroup
		gate := make(chan struct{})
		for i := range procs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-gate
				procs[i] = startAgentRaw(e.ring, e.sock, e.home, pass(0))
			}()
		}
		close(gate)
		wg.Wait()
		time.Sleep(4 * time.Second) // unlock (argon2) then Listen; every loser has failed by now
		alive, inUse, other := 0, 0, 0
		var winner *aproc
		for _, p := range procs {
			if !p.exited1() {
				alive++
				winner = p
			} else if p.code == 1 && strings.Contains(p.log.String(), "already listening") {
				inUse++
			} else {
				other++
			}
		}
		if alive != 1 || other != 0 || inUse != racers-1 {
			t.Errorf("round %d: alive=%d refused-in-use=%d other=%d (want 1, %d, 0)", r, alive, inUse, other, racers-1)
			for i, p := range procs {
				t.Logf("  racer %d: exited=%v code=%d log=%q", i, p.exited1(), p.code, p.log.String())
			}
		}
		if winner != nil {
			if err := signOnce(e.sock, []byte("after-race"), e.pub); err != nil {
				t.Errorf("round %d: the winner does not answer: %v", r, err)
			}
			winner.cmd.Process.Signal(syscall.SIGTERM)
			winner.wait(t, 5*time.Second)
		}
		winners[alive]++
		for _, p := range procs {
			if !p.exited1() {
				killProc(p.cmd.Process)
				p.wait(t, 2*time.Second)
			}
		}
	}
	t.Logf("rounds=%d racers=%d rounds-with-exactly-one-winner=%d", rounds, racers, winners[1])
	record("agent-race-start", map[string]any{"rounds": rounds, "racers": racers, "exactly_one": winners[1]})
}

// TestAgentStaleSocket: SIGKILL leaves the socket file behind; a new agent must take over.
func TestAgentStaleSocket(t *testing.T) {
	need(t)
	rounds := envInt("TOPO_STALE_ROUNDS", 10)
	e := newAgentEnv(t)
	for r := 0; r < rounds; r++ {
		a := e.start(t)
		killProc(a.cmd.Process)
		a.wait(t, 3*time.Second)
		st, err := os.Lstat(e.sock)
		if err != nil || st.Mode()&os.ModeSocket == 0 {
			t.Fatalf("round %d: expected a stale socket after SIGKILL: %v", r, err)
		}
		_, derr := net.Dial("unix", e.sock)
		if !errors.Is(derr, syscall.ECONNREFUSED) {
			t.Errorf("round %d: dial of the stale socket = %v, want ECONNREFUSED", r, derr)
		}
		if err := signOnce(e.sock, []byte("x"), e.pub); err == nil {
			t.Errorf("round %d: sign succeeded against a stale socket", r)
		}
		b := startAgentRaw(e.ring, e.sock, e.home, pass(0))
		if !b.waitReady(e.sock) {
			t.Fatalf("round %d: replacement agent did not start over the stale socket: %s", r, b.log.String())
		}
		if err := signOnce(e.sock, []byte("y"), e.pub); err != nil {
			t.Errorf("round %d: replacement does not sign: %v", r, err)
		}
		killProc(b.cmd.Process) // leave another stale one for the next round
		b.wait(t, 3*time.Second)
	}
	t.Logf("rounds=%d (SIGKILL, stale socket, takeover)", rounds)
	record("agent-stale-socket", map[string]any{"rounds": rounds})
}

// TestAgentSocketRemoved: the A5-L2 stop. Removing the socket stops the agent within
// about 10 s with exit 1 and no key left; a replacement file at the path is left alone.
func TestAgentSocketRemoved(t *testing.T) {
	need(t)
	for _, variant := range []string{"removed", "replaced"} {
		e := newAgentEnv(t)
		a := e.start(t)
		hc, err := rawConn(e.sock)
		if err != nil {
			t.Fatal(err)
		}
		t0 := time.Now()
		os.Remove(e.sock)
		const marker = "not-a-socket-marker"
		if variant == "replaced" {
			os.WriteFile(e.sock, []byte(marker), 0o600)
		}
		if !a.wait(t, 15*time.Second) {
			t.Fatalf("%s: agent still alive 15s after its socket vanished (holds a key nobody can reach)", variant)
		}
		d := a.exited.Sub(t0)
		if a.code != 1 {
			t.Errorf("%s: exit code %d, want 1; log=%s", variant, a.code, a.log.String())
		}
		if !strings.Contains(a.log.String(), "removed or replaced") {
			t.Errorf("%s: log does not explain the stop: %s", variant, a.log.String())
		}
		hc.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := hc.Read(make([]byte, 1)); err == nil {
			t.Errorf("%s: held connection still open after the agent stopped", variant)
		}
		if variant == "replaced" {
			if b, err := os.ReadFile(e.sock); err != nil || string(b) != marker {
				t.Errorf("replaced: the agent touched the file that replaced its socket (%q, %v)", b, err)
			}
		}
		t.Logf("%s: agent stopped %v after the socket vanished, exit %d", variant, d.Round(100*time.Millisecond), a.code)
		record("agent-socket-"+variant, map[string]any{"stop_after_ms": d.Milliseconds(), "exit": a.code})
	}
}
