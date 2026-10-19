//go:build topology

package topology

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/netstar-labs/keystore/pkg/agent"
	"github.com/netstar-labs/keystore/pkg/keystore"
)

// TestFleet: a scripted fleet of TOPO_FLEET (default 24) concurrent client processes signs
// through agents and directly from the ring while an operator rotates the ring on disk:
// add k2, passwd, use k2, start a second agent on the new key, rm k1, then again for k3.
// Every signature must verify under the key the process says it used (its "signing with
// SHA256:..." line), agent-A1 clients must keep getting k1 signatures after k1 is gone from
// the ring and the passphrase has changed twice (a running agent keeps the key it loaded;
// documented), and no agent may ever sign under a key it was not started with.
func TestFleet(t *testing.T) {
	need(t)
	fleet := envInt("TOPO_FLEET", 24)
	phase := time.Duration(envInt("TOPO_FLEET_PHASE_MS", 2500)) * time.Millisecond
	dir := workDir(t)
	ring := filepath.Join(dir, "r.ks")
	home := filepath.Join(dir, "h")
	os.Mkdir(home, 0o700)
	sd := filepath.Join(dir, "s")
	os.Mkdir(sd, 0o700)
	sock := func(n int) string { return filepath.Join(sd, fmt.Sprintf("a%d.sock", n)) }

	if r := ks(home, pass(0), "", "keygen", "-keystore", ring, "-id", "k1"); !r.ok() {
		t.Fatalf("keygen: %s", r.stderr)
	}
	var pubMu sync.Mutex
	pubs := map[string]ed25519.PublicKey{} // fingerprint -> key, for every key that ever existed
	idFP := map[string]string{}
	learn := func(id string) ed25519.PublicKey {
		r := ks(home, "", "", "export-pub", "-keystore", ring, "-id", id)
		p, err := parsePub(r.stdout)
		if err != nil {
			t.Fatalf("export-pub %s: %v %s", id, err, r.stderr)
		}
		pubMu.Lock()
		pubs[keystore.Fingerprint(p)] = p
		idFP[id] = keystore.Fingerprint(p)
		pubMu.Unlock()
		return p
	}
	k1 := learn("k1")

	var (
		gen, epoch atomic.Int64
		inflight   atomic.Int64
		maxInfl    atomic.Int64
		mu         sync.Mutex
		count      = map[string]int{}
		viol       []string
		stop       = make(chan struct{})
		oldAgentOK atomic.Int64 // A1 signatures obtained after k1 was removed from the ring
		k1Removed  atomic.Bool
	)
	bump := func(k string) { mu.Lock(); count[k]++; mu.Unlock() }
	fail := func(f string, a ...any) { mu.Lock(); viol = append(viol, fmt.Sprintf(f, a...)); mu.Unlock() }

	// one signing process; want is the fingerprint the process MUST report ("" = any known key).
	one := func(kind string, w, seq int, args []string, env []string, wantFP string, wantPub ed25519.PublicKey) {
		msg := []byte(fmt.Sprintf("fleet-%s-%d-%d-%d", kind, w, seq, time.Now().UnixNano()))
		n := inflight.Add(1)
		for {
			m := maxInfl.Load()
			if n <= m || maxInfl.CompareAndSwap(m, n) {
				break
			}
		}
		r := runEnv(append(cleanEnv(home), env...), msg, bin("keystore"), args...)
		inflight.Add(-1)
		if r.code != 0 {
			bump(kind + "/" + classify(r))
			if c := classify(r); c != oPass {
				fail("%s: %s", kind, r.stderr)
			}
			return
		}
		fp := ""
		for _, ln := range strings.Split(r.stderr, "\n") {
			if f, ok := strings.CutPrefix(ln, "signing with "); ok {
				fp = strings.TrimSpace(f)
			}
		}
		sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(r.stdout))
		if err != nil || fp == "" {
			fail("%s: unparsable output %q %q", kind, r.stdout, r.stderr)
			return
		}
		pubMu.Lock()
		pub := pubs[fp]
		pubMu.Unlock()
		if pub == nil {
			fail("%s: signed under unknown key %s", kind, fp)
			return
		}
		if wantFP != "" && fp != wantFP {
			fail("%s: signed under %s, want %s", kind, fp, wantFP)
		}
		if !ed25519.Verify(pub, msg, sig) {
			fail("%s: signature does not verify under the key it names (%s)", kind, fp)
			return
		}
		if wantPub != nil && !ed25519.Verify(wantPub, msg, sig) {
			fail("%s: signature does not verify under the expected key", kind)
			return
		}
		bump(kind + "/ok")
		if kind == "agent1" && k1Removed.Load() {
			oldAgentOK.Add(1)
		}
	}

	a1 := startAgentRaw(ring, sock(1), home, pass(0), "-id", "k1")
	if !a1.waitReady(sock(1)) {
		t.Fatalf("agent 1: %s", a1.log.String())
	}
	var a2, a3 *aproc
	var a2pub, a3pub ed25519.PublicKey
	var a2up, a3up atomic.Bool

	var wg sync.WaitGroup
	for w := 0; w < fleet; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for seq := 0; ; seq++ {
				select {
				case <-stop:
					return
				default:
				}
				switch {
				case w%24 < 12: // old agent
					one("agent1", w, seq, []string{"sign", "-agent", sock(1)}, nil, idFPof(&pubMu, idFP, "k1"), k1)
				case w%24 < 18: // new agent once it exists, else the old one
					if a2up.Load() {
						fpv := idFPof(&pubMu, idFP, "k2")
						one("agent2", w, seq, []string{"sign", "-agent", sock(2)}, nil, fpv, a2pub)
					} else {
						one("agent1", w, seq, []string{"sign", "-agent", sock(1)}, nil, idFPof(&pubMu, idFP, "k1"), k1)
					}
				case w%24 < 20:
					if a3up.Load() {
						one("agent3", w, seq, []string{"sign", "-agent", sock(3)}, nil, idFPof(&pubMu, idFP, "k3"), a3pub)
					} else {
						time.Sleep(50 * time.Millisecond)
					}
				default: // straight from the ring, which is being rotated underneath
					e1 := epoch.Load()
					g := gen.Load()
					mu.Lock()
					before := count["ring/stale-pass"]
					mu.Unlock()
					one("ring", w, seq, []string{"sign", "-keystore", ring}, []string{"KEYSTORE_PASSPHRASE=" + pass(int(g))}, "", nil)
					mu.Lock()
					after := count["ring/stale-pass"]
					mu.Unlock()
					if e1%2 == 0 && epoch.Load() == e1 && after != before {
						fail("ring sign refused the passphrase with no rotation in flight")
					}
				}
			}
		}()
	}

	op := func(name string, r result) {
		if !r.ok() {
			fail("operator %s: %s", name, r.stderr)
		}
	}
	rotate := func(from int) {
		epoch.Add(1)
		op("passwd", ks(home, pass(from), pass(from+1), "passwd", "-keystore", ring))
		gen.Store(int64(from + 1))
		epoch.Add(1)
	}
	time.Sleep(phase) // baseline: only k1 exists

	op("add k2", ks(home, pass(0), "", "add", "-keystore", ring, "-id", "k2"))
	a2pub = learn("k2")
	time.Sleep(phase / 2)
	rotate(0)
	time.Sleep(phase / 2)
	op("use k2", ks(home, "", "", "use", "-keystore", ring, "-id", "k2"))
	a2 = startAgentRaw(ring, sock(2), home, pass(1), "-id", "k2")
	if !a2.waitReady(sock(2)) {
		t.Fatalf("agent 2: %s", a2.log.String())
	}
	a2up.Store(true)
	time.Sleep(phase)
	op("rm k1", ks(home, "", "", "rm", "-keystore", ring, "-id", "k1"))
	k1Removed.Store(true)
	time.Sleep(phase)

	op("add k3", ks(home, pass(1), "", "add", "-keystore", ring, "-id", "k3"))
	a3pub = learn("k3")
	rotate(1)
	op("use k3", ks(home, "", "", "use", "-keystore", ring, "-id", "k3"))
	a3 = startAgentRaw(ring, sock(3), home, pass(2), "-id", "k3")
	if !a3.waitReady(sock(3)) {
		t.Fatalf("agent 3: %s", a3.log.String())
	}
	a3up.Store(true)
	time.Sleep(phase)

	close(stop)
	wg.Wait()

	// The old agent must still hold k1: the ring has no k1 and two new passphrases.
	// (Documented: a running agent keeps signing the key it loaded.)
	if oldAgentOK.Load() == 0 {
		t.Errorf("no agent-1 signature succeeded after k1 was removed from the ring")
	}
	// Absence checks: agent 1 never signed under k2/k3, agent 2 never under k1 or k3.
	cross := []struct {
		sock string
		not  []ed25519.PublicKey
	}{{sock(1), []ed25519.PublicKey{a2pub, a3pub}}, {sock(2), []ed25519.PublicKey{k1, a3pub}}, {sock(3), []ed25519.PublicKey{k1, a2pub}}}
	for _, c := range cross {
		msg := []byte("final-cross-check")
		cl, err := dialSign(c.sock, msg)
		if err != nil {
			t.Errorf("final sign via %s: %v", c.sock, err)
			continue
		}
		for _, bad := range c.not {
			if ed25519.Verify(bad, msg, cl) {
				t.Errorf("a signature from %s verifies under a key that agent was not started with", c.sock)
			}
		}
	}
	// ring direct now: current is k3 under pass(2), k1 gone, k2 still present.
	if r := ks(home, pass(2), "", "list", "-keystore", ring); !strings.Contains(r.stdout, "k3") || strings.Contains(r.stdout, "k1") {
		t.Errorf("final ring list: %q", r.stdout)
	}
	for _, a := range []*aproc{a1, a2, a3} {
		a.cmd.Process.Signal(syscall.SIGTERM)
		a.wait(t, 5*time.Second)
	}
	for _, v := range viol {
		t.Error("VIOLATION:", v)
	}
	total := 0
	for k, v := range count {
		t.Logf("%-20s %d", k, v)
		if strings.HasSuffix(k, "/ok") {
			total += v
		}
	}
	t.Logf("fleet=%d signatures-verified=%d max-concurrent-client-processes=%d agent1-signs-after-k1-removed=%d", fleet, total, maxInfl.Load(), oldAgentOK.Load())
	record("fleet", map[string]any{"fleet": fleet, "verified": total, "max_concurrent": maxInfl.Load(), "agent1_after_rm": oldAgentOK.Load(),
		"violations": len(viol), "outcomes": count})
}

func idFPof(mu *sync.Mutex, m map[string]string, id string) string {
	mu.Lock()
	defer mu.Unlock()
	return m[id]
}

func dialSign(sock string, msg []byte) ([]byte, error) {
	c, err := agent.Dial(sock)
	if err != nil {
		return nil, err
	}
	return c.Sign(nil, msg, nil)
}
