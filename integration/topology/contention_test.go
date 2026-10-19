//go:build topology

package topology

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netstar-labs/keystore/internal/ringfile"
)

// TestContention runs TOPO_WORKERS concurrent worker loops, each spawning real
// `keystore add|rm|use` processes against one ring, while one loop rotates the passphrase
// with `keystore passwd` and a checker snapshots the ring. Every worker owns its ids, so
// the expected final ring is computable exactly: the seed plus every successful add minus
// every successful rm. Properties 3 (never torn), 4 (no lost write) and 5 (one passphrase)
// are asserted on the final ring and, sampled, on the live one.
func TestContention(t *testing.T) {
	need(t)
	workers := envInt("TOPO_WORKERS", 16)
	total := int64(envInt("TOPO_OPS", 300))
	dir := workDir(t)
	ring := filepath.Join(dir, "ring.ks")
	scratch := filepath.Join(dir, "scratch")
	os.Mkdir(scratch, 0o700)
	home := filepath.Join(dir, "home")
	os.Mkdir(home, 0o700)

	if r := ks(home, pass(0), "", "keygen", "-keystore", ring, "-id", "seed"); !r.ok() {
		t.Fatalf("keygen: %+v", r)
	}

	var (
		gen   atomic.Int64 // generation of the ring passphrase; bumped after a passwd commits
		epoch atomic.Int64 // odd while a passwd is in flight; adders ignore stale-pass across it
		done  atomic.Int64
		stop  = make(chan struct{})
		mu    sync.Mutex
		count = map[string]int{} // op/outcome -> n
		viol  []string
		live  = make([][]string, workers) // each worker's live ids; written only by that worker
	)
	bump := func(k string) { mu.Lock(); count[k]++; mu.Unlock() }
	fail := func(f string, a ...any) { mu.Lock(); viol = append(viol, fmt.Sprintf(f, a...)); mu.Unlock() }

	var wg sync.WaitGroup
	t0 := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(uint64(w), 7))
			seq := 0
			for done.Add(1) <= total {
				e1 := epoch.Load()
				g := gen.Load()
				stable := e1%2 == 0
				var r result
				var op string
				switch x := rng.IntN(100); {
				case x < 8: // adds with a wrong passphrase must NEVER succeed (property 5)
					op = "add-wrongpass"
					r = ks(home, "not-the-ring-passphrase", "", "add", "-keystore", ring, "-id", fmt.Sprintf("bad%d-%d", w, seq))
					seq++
					if r.ok() {
						fail("add with a wrong passphrase succeeded")
					}
				case x < 55 || len(live[w]) == 0:
					op = "add"
					id := fmt.Sprintf("w%d-%d", w, seq)
					seq++
					r = ks(home, pass(int(g)), "", "add", "-keystore", ring, "-id", id)
					switch c := classify(r); c {
					case oOK:
						live[w] = append(live[w], id)
					case oLocked:
					case oPass:
						if stable && epoch.Load() == e1 {
							fail("add: passphrase refused with no passwd in flight: %s", r.stderr)
						}
					default:
						fail("add %s: %s", id, r.stderr)
					}
				case x < 80:
					op = "rm"
					i := rng.IntN(len(live[w]))
					id := live[w][i]
					r = ks(home, "", "", "rm", "-keystore", ring, "-id", id)
					switch c := classify(r); c {
					case oOK:
						live[w] = slices.Delete(live[w], i, i+1)
					case oLocked:
					default:
						fail("rm %s: %s", id, r.stderr)
					}
				default:
					op = "use"
					id := "seed"
					if len(live[w]) > 0 && rng.IntN(2) == 0 {
						id = live[w][rng.IntN(len(live[w]))]
					}
					r = ks(home, "", "", "use", "-keystore", ring, "-id", id)
					if c := classify(r); c != oOK && c != oLocked {
						fail("use %s: %s", id, r.stderr)
					}
				}
				bump(op + "/" + classify(r))
			}
		}()
	}

	// One passwd loop: the only writer of gen, so its view of the passphrase is exact.
	var pwWG sync.WaitGroup
	pwWG.Add(1)
	go func() {
		defer pwWG.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(1500 * time.Millisecond):
			}
			g := gen.Load()
			epoch.Add(1)
			r := ks(home, pass(int(g)), pass(int(g)+1), "passwd", "-keystore", ring)
			c := classify(r)
			if c == oOK {
				gen.Add(1)
			}
			epoch.Add(1)
			bump("passwd/" + c)
			if c != oOK && c != oLocked {
				fail("passwd: %s", r.stderr)
			}
		}
	}()

	// Checker: snapshot the live ring; it must parse, and the seed plus two other entries
	// must unlock under one and the same generation.
	var chk atomic.Int64
	var chWG sync.WaitGroup
	chWG.Add(1)
	go func() {
		defer chWG.Done()
		rng := rand.New(rand.NewPCG(99, 1))
		for {
			select {
			case <-stop:
				return
			case <-time.After(700 * time.Millisecond):
			}
			g0 := gen.Load()
			snap, f, err := snapshot(t, ring, scratch)
			if err != nil {
				fail("checker: %v", err)
				continue
			}
			g1 := gen.Load()
			// `current` must always name an existing signing entry (the seed is never removed,
			// so it can never be empty either).
			if e := f.Find(f.Current); f.Current == "" || e == nil || e.Kind != ringfile.KindEd25519 {
				fail("checker: current %q does not name a signing entry", f.Current)
			}
			found := -1
			for cand := g0 - 1; cand <= g1+1; cand++ {
				if cand >= 0 && unlocksWith(snap, "seed", pass(int(cand))) {
					found = int(cand)
					break
				}
			}
			if found < 0 {
				fail("checker: seed unlocks under no generation in [%d,%d]", g0-1, g1+1)
				continue
			}
			for n := 0; n < 2 && len(f.Entries) > 1; n++ {
				e := f.Entries[rng.IntN(len(f.Entries))]
				if !unlocksWith(snap, e.ID, pass(found)) {
					fail("checker: entry %s does not unlock under the passphrase that unlocks seed (gen %d): property 5", e.ID, found)
				}
			}
			os.Remove(snap)
			chk.Add(1)
		}
	}()

	wg.Wait()
	close(stop)
	pwWG.Wait()
	chWG.Wait()
	elapsed := time.Since(t0)

	// ---- final state ----
	_, f, err := snapshot(t, ring, scratch)
	if err != nil {
		t.Fatalf("final ring: %v", err)
	}
	want := []string{"seed"}
	for _, l := range live {
		want = append(want, l...)
	}
	sort.Strings(want)
	if got := ids(f); !slices.Equal(got, want) {
		t.Errorf("entry set differs from the model: lost or phantom writes\n got %d: %v\nwant %d: %v", len(got), got, len(want), want)
	}
	g := gen.Load()
	for _, e := range f.Entries {
		if !unlocksWith(ring, e.ID, pass(int(g))) {
			t.Errorf("entry %s does not unlock under the final passphrase (gen %d)", e.ID, g)
		}
	}
	if f.Current == "" || f.Find(f.Current) == nil {
		t.Errorf("current %q does not name an entry", f.Current)
	}
	if st, err := os.Stat(ring); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("ring mode: %v %v", st, err)
	}
	os.RemoveAll(scratch)
	if tmps, other := debris(dir, "ring.ks"); len(tmps) != 0 || len(other) != 0 {
		// home/ is ours; anything else is debris
		other = slices.DeleteFunc(other, func(s string) bool { return s == "home" })
		if len(tmps) != 0 || len(other) != 0 {
			t.Errorf("debris after a run with no kills: tmp=%v other=%v", tmps, other)
		}
	}
	for _, v := range viol {
		t.Error("VIOLATION:", v)
	}
	var keys []string
	for k := range count {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("%-24s %d", k, count[k])
	}
	t.Logf("workers=%d ops=%d elapsed=%v passwd-generations=%d live-checks=%d final-entries=%d",
		workers, total, elapsed.Round(time.Millisecond), g, chk.Load(), len(f.Entries))
	kv := map[string]any{"workers": workers, "ops": total, "elapsed_s": elapsed.Seconds(), "passwd_gens": g,
		"live_checks": chk.Load(), "final_entries": len(f.Entries), "violations": len(viol), "outcomes": count}
	record("contention", kv)
}
