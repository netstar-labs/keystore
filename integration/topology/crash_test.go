//go:build topology

package topology

import (
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/netstar-labs/keystore/internal/ringfile"
)

// state is the model of a ring: which ids it holds, which is current and which
// passphrase generation encrypts it.
type state struct {
	ids     []string // sorted
	current string
	gen     int
}

func (s state) equal(o state) bool {
	return s.current == o.current && s.gen == o.gen && slices.Equal(s.ids, o.ids)
}

func (s state) String() string { return fmt.Sprintf("{%v current=%s gen=%d}", s.ids, s.current, s.gen) }

// TestCrashLoop SIGKILLs a real writer at a random instant, TOPO_ITERS times in total
// (split over TOPO_LANES independent rings run in parallel). After every kill the ring
// must parse and equal exactly the state before the write or the state after it (never
// anything else), the lock must not wedge (the next writer succeeds at once), and the
// only debris allowed is one documented .tmp file per kill, which is counted.
func TestCrashLoop(t *testing.T) {
	need(t)
	iters := envInt("TOPO_ITERS", 60)
	lanes := envInt("TOPO_LANES", 4)
	seed := uint64(envInt("TOPO_SEED", int(time.Now().Unix())))
	t.Logf("seed=%d iters=%d lanes=%d (TOPO_SEED reproduces the kill delays, not the kernel's scheduling)", seed, iters, lanes)
	if lanes > iters {
		lanes = iters
	}

	type tally struct {
		mu                             sync.Mutex
		n                              map[string]int // op/outcome
		kills, completed, tmps, maxTmp int
		viol                           []string
	}
	tl := &tally{n: map[string]int{}}
	fail := func(f string, a ...any) {
		tl.mu.Lock()
		tl.viol = append(tl.viol, fmt.Sprintf(f, a...))
		tl.mu.Unlock()
	}

	var wg sync.WaitGroup
	t0 := time.Now()
	for lane := 0; lane < lanes; lane++ {
		n := iters / lanes
		if lane < iters%lanes {
			n++
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			runLane(t, lane, n, seed+uint64(lane), func(k string, kill, comp, tmps int) {
				tl.mu.Lock()
				tl.n[k]++
				tl.kills += kill
				tl.completed += comp
				tl.tmps += tmps
				tl.maxTmp = max(tl.maxTmp, tmps)
				tl.mu.Unlock()
			}, fail)
		}()
	}
	wg.Wait()
	el := time.Since(t0)
	var keys []string
	for k := range tl.n {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("%-22s %d", k, tl.n[k])
	}
	for _, v := range tl.viol {
		t.Error("VIOLATION:", v)
	}
	t.Logf("iterations=%d killed-by-SIGKILL=%d ran-to-completion=%d stale-tmp-files=%d elapsed=%v", iters, tl.kills, tl.completed, tl.tmps, el.Round(time.Second))
	record("crashloop", map[string]any{"iters": iters, "lanes": lanes, "seed": seed, "killed": tl.kills, "completed": tl.completed,
		"stale_tmp": tl.tmps, "elapsed_s": el.Seconds(), "violations": len(tl.viol), "outcomes": tl.n})
}

func runLane(t *testing.T, lane, iters int, seed uint64, tally func(k string, kill, comp, tmps int), fail func(string, ...any)) {
	dir := workDir(t)
	ring := filepath.Join(dir, "r.ks")
	home := filepath.Join(dir, "h")
	os.Mkdir(home, 0o700)
	scratch := filepath.Join(dir, "s")
	os.Mkdir(scratch, 0o700)
	rng := rand.New(rand.NewPCG(seed, 0xc0ffee))

	if r := ks(home, pass(0), "", "keygen", "-keystore", ring, "-id", "seed"); !r.ok() {
		fail("lane %d keygen: %s", lane, r.stderr)
		return
	}
	model := state{ids: []string{"seed"}, current: "seed", gen: 0}
	seq := 0
	add := func(s state) (state, string) {
		seq++
		id := fmt.Sprintf("k%d", seq)
		n := state{ids: append(slices.Clone(s.ids), id), current: s.current, gen: s.gen}
		sort.Strings(n.ids)
		return n, id
	}
	// Calibrate how long each op takes unmolested, so kill delays span the whole op.
	calib := map[string]time.Duration{}
	calibMin := map[string]time.Duration{}
	for i := 0; i < 3; i++ {
		var id string
		model, id = add(model)
		r := ks(home, pass(model.gen), "", "add", "-keystore", ring, "-id", id)
		if !r.ok() {
			fail("lane %d calibration add: %s", lane, r.stderr)
			return
		}
		calib["add"] = max(calib["add"], r.dur)
		calibMin["add"] = minNZ(calibMin["add"], r.dur)
		r = ks(home, "", "", "use", "-keystore", ring, "-id", id)
		calib["use"] = max(calib["use"], r.dur)
		calibMin["use"] = minNZ(calibMin["use"], r.dur)
		r = ks(home, "", "", "use", "-keystore", ring, "-id", "seed")
		r = ks(home, pass(model.gen), pass(model.gen+1), "passwd", "-keystore", ring)
		if !r.ok() {
			fail("lane %d calibration passwd: %s", lane, r.stderr)
			return
		}
		model.gen++
		calib["passwd"] = max(calib["passwd"], r.dur)
		calibMin["passwd"] = minNZ(calibMin["passwd"], r.dur)
	}
	// calibration leaves current == seed; remove one entry to measure rm and shrink the ring
	r := ks(home, "", "", "rm", "-keystore", ring, "-id", model.ids[1])
	calib["rm"], calibMin["rm"] = r.dur, r.dur
	model.ids = slices.Delete(model.ids, 1, 2)

	for it := 0; it < iters; it++ {
		// choose the op and its expected new state
		var op string
		var args []string
		var env []string
		var next state
		pick := rng.IntN(100)
		switch {
		case pick < 35 && len(model.ids) < 6, len(model.ids) <= 2 && pick < 70:
			var id string
			next, id = add(model)
			op, args, env = "add", []string{"add", "-keystore", ring, "-id", id}, []string{"KEYSTORE_PASSPHRASE=" + pass(model.gen)}
		case pick < 55 && len(model.ids) > 2:
			var cand []string // never the seed, which is always current here (the probe sets it)
			for _, c := range model.ids {
				if c != "seed" && c != model.current {
					cand = append(cand, c)
				}
			}
			id := cand[rng.IntN(len(cand))]
			next = state{ids: slices.DeleteFunc(slices.Clone(model.ids), func(s string) bool { return s == id }), current: model.current, gen: model.gen}
			op, args = "rm", []string{"rm", "-keystore", ring, "-id", id}
		case pick < 70:
			other := model.ids[0]
			if other == "seed" {
				other = model.ids[1]
			}
			next = state{ids: model.ids, current: other, gen: model.gen}
			op, args = "use", []string{"use", "-keystore", ring, "-id", other}
		default:
			next = state{ids: model.ids, current: model.current, gen: model.gen + 1}
			op, args = "passwd", []string{"passwd", "-keystore", ring}
			env = []string{"KEYSTORE_PASSPHRASE=" + pass(model.gen), "KEYSTORE_NEW_PASSPHRASE=" + pass(model.gen+1)}
		}
		if !slices.Contains(next.ids, next.current) {
			fail("lane %d: model bug", lane)
			return
		}

		cmd := exec.Command(bin("keystore"), args...)
		cmd.Env = append(cleanEnv(home), env...)
		// Uniform over the whole op, except that 40% of kills are aimed at the tail: the last
		// stretch before the op's fastest observed finish, where the temp file is written,
		// renamed and the directory synced. Uniform sampling alone hits that few-millisecond
		// window about once in a hundred kills.
		delay := time.Duration(rng.Float64() * 1.25 * float64(calib[op]))
		if rng.IntN(100) < 40 {
			lo := max(0, calibMin[op]-25*time.Millisecond)
			hi := calib[op] + 10*time.Millisecond
			delay = lo + time.Duration(rng.Float64()*float64(hi-lo))
		}
		if err := cmd.Start(); err != nil {
			fail("lane %d start: %v", lane, err)
			return
		}
		time.Sleep(delay)
		killProc(cmd.Process)
		werr := cmd.Wait()
		killed := false
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL {
			killed = true
		}
		if !killed && werr != nil {
			fail("lane %d it %d: %s exited on its own with %v (no contention, so any failure is a defect)", lane, it, op, werr)
			return
		}

		// ---- what is on disk now? ----
		snap, f, err := snapshot(t, ring, scratch)
		if err != nil {
			fail("lane %d it %d: after killing %s: %v", lane, it, op, err)
			return
		}
		obs := state{ids: ids(f), current: f.Current, gen: -1}
		for _, g := range []int{model.gen, next.gen} {
			if unlocksWith(snap, "seed", pass(g)) {
				obs.gen = g
				break
			}
		}
		verdict := "?"
		switch {
		case obs.equal(model) && !next.equal(model):
			verdict = "old"
		case obs.equal(next):
			verdict = "new"
		default:
			fail("lane %d it %d: after killing %s the ring is neither old nor new\n  old %v\n  new %v\n  got %v", lane, it, op, model, next, obs)
			return
		}
		// Every entry must unlock under the one generation: all of them after a passwd (the
		// only op that rewrites every ciphertext), seed plus one sample otherwise.
		check := f.Entries
		if op != "passwd" && len(check) > 2 {
			check = []ringfile.Entry{f.Entries[0], f.Entries[rng.IntN(len(f.Entries))]}
		}
		for _, e := range check {
			if !unlocksWith(snap, e.ID, pass(obs.gen)) {
				fail("lane %d it %d: entry %s does not unlock under gen %d after killing %s (property 5)", lane, it, e.ID, obs.gen, op)
			}
		}
		os.Remove(snap)

		// ---- debris ----
		tmps, other := debris(dir, "r.ks")
		other = slices.DeleteFunc(other, func(s string) bool { return s == "h" || s == "s" })
		if len(other) != 0 {
			fail("lane %d it %d: unexpected files %v", lane, it, other)
		}
		if len(tmps) > 1 || (!killed && len(tmps) != 0) {
			fail("lane %d it %d: %d stale temp files after %s (killed=%v): %v", lane, it, len(tmps), op, killed, tmps)
		}
		for _, n := range tmps {
			if st, err := os.Stat(filepath.Join(dir, n)); err == nil && st.Mode().Perm() != 0o600 {
				fail("lane %d it %d: stale temp %s has mode %v, want 0600", lane, it, n, st.Mode().Perm())
			}
			os.Remove(filepath.Join(dir, n)) // the documented operator cleanup; counted above
		}
		model = obs

		// ---- the lock must not be wedged: the next writer succeeds, promptly ----
		pr := ks(home, "", "", "use", "-keystore", ring, "-id", "seed")
		if !pr.ok() || pr.dur > 3*time.Second {
			fail("lane %d it %d: probe writer after killing %s: code=%d dur=%v %s (lock wedged?)", lane, it, op, pr.code, pr.dur, pr.stderr)
			return
		}
		model.current = "seed"

		k := op + "/" + verdict
		if !killed {
			k += "/exited-first"
		}
		kc, cc := 0, 0
		if killed {
			kc = 1
		} else {
			cc = 1
		}
		tally(k, kc, cc, len(tmps))
	}
	// final: whole ring unlocks under the tracked generation
	_, f, err := snapshot(t, ring, scratch)
	if err != nil {
		fail("lane %d final: %v", lane, err)
		return
	}
	for _, e := range f.Entries {
		if !unlocksWith(ring, e.ID, pass(model.gen)) {
			fail("lane %d final: entry %s does not unlock under gen %d", lane, e.ID, model.gen)
		}
	}
}

func minNZ(a, b time.Duration) time.Duration {
	if a == 0 || b < a {
		return b
	}
	return a
}
