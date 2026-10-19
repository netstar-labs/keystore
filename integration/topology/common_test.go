//go:build topology

package topology

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/netstar-labs/keystore/internal/ringfile"
	"github.com/netstar-labs/keystore/pkg/keystore"
)

// Knobs, all environment variables so one driver script scales every test.
//
//	KEYSTORE_TOPOLOGY=1  required, else every test skips
//	TOPO_BIN             directory holding the keystore and keystore-agent binaries
//	TOPO_DIR             base directory for work (default: the OS temp dir)
//	TOPO_OUT             file that result lines (JSON) are appended to
func TestMain(m *testing.M) {
	if os.Getenv("TOPO_HELPER") != "" {
		helperMain() // a re-executed test binary acting as a raw agent client (see xuid_test.go)
		return
	}
	os.Exit(m.Run())
}

func need(t *testing.T) {
	t.Helper()
	if os.Getenv("KEYSTORE_TOPOLOGY") != "1" {
		t.Skip("set KEYSTORE_TOPOLOGY=1 to run the topology tier")
	}
	if os.Getenv("TOPO_BIN") == "" {
		t.Skip("set TOPO_BIN to the directory holding the keystore and keystore-agent binaries")
	}
}

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func bin(name string) string { return filepath.Join(os.Getenv("TOPO_BIN"), name) }

// workDir makes a short, private directory (unix socket paths are limited to ~103 bytes).
func workDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp(os.Getenv("TOPO_DIR"), "tp")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// pass returns the n-th test passphrase (>= 12 characters).
func pass(n int) string { return fmt.Sprintf("topo-passphrase-%04d", n) }

// cleanEnv is the environment every child gets: no keychain variable, no inherited
// passphrase, a throwaway HOME. The real security(1) is therefore unreachable.
func cleanEnv(home string, extra ...string) []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "TMPDIR=" + home}
	return append(env, extra...)
}

type result struct {
	code   int
	stdout string
	stderr string
	dur    time.Duration
}

func (r result) ok() bool { return r.code == 0 }

// ks runs the keystore CLI to completion with the given passphrase(s) in its environment.
func ks(home, pw, newPw string, args ...string) result {
	env := cleanEnv(home)
	if pw != "" {
		env = append(env, "KEYSTORE_PASSPHRASE="+pw)
	}
	if newPw != "" {
		env = append(env, "KEYSTORE_NEW_PASSPHRASE="+newPw)
	}
	return runEnv(env, nil, bin("keystore"), args...)
}

func runEnv(env []string, stdin []byte, name string, args ...string) result {
	cmd := exec.Command(name, args...)
	cmd.Env = env
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	t0 := time.Now()
	err := cmd.Run()
	r := result{stdout: so.String(), stderr: se.String(), dur: time.Since(t0)}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			r.code = ee.ExitCode() // -1 when killed by a signal
		} else {
			r.code = -2
			r.stderr += err.Error()
		}
	}
	return r
}

// Failure classes of a CLI mutation, from its stderr. Anything else is a violation.
const (
	oOK     = "ok"
	oLocked = "locked"     // ErrLocked: the lock was never taken, nothing was written
	oPass   = "stale-pass" // ErrPassphraseMismatch / ErrBadPass: wrong passphrase for the ring
	oExists = "exists"
	oNoKey  = "nokey"
	oOther  = "other"
)

func classify(r result) string {
	switch {
	case r.code == 0:
		return oOK
	case strings.Contains(r.stderr, "locked by another process"):
		return oLocked
	case strings.Contains(r.stderr, "passphrase does not match"), strings.Contains(r.stderr, "wrong passphrase"),
		strings.Contains(r.stderr, "authentication failed"), strings.Contains(r.stderr, "cannot decrypt"):
		return oPass
	case strings.Contains(r.stderr, "already exists"):
		return oExists
	case strings.Contains(r.stderr, "no such entry"):
		return oNoKey
	}
	return oOther
}

// snapshot reads the ring bytes once and returns a private copy of them, so that every
// later check works on one atomic state even while writers keep renaming over the ring.
func snapshot(t testing.TB, ring, scratch string) (string, *ringfile.File, error) {
	b, err := os.ReadFile(ring)
	if err != nil {
		return "", nil, err
	}
	f, err := ringfile.Parse(b)
	if err != nil {
		return "", nil, fmt.Errorf("ring does not parse: %w", err)
	}
	cp := filepath.Join(scratch, "snap-"+strconv.FormatInt(time.Now().UnixNano(), 36)+".ks")
	if err := os.WriteFile(cp, b, 0o600); err != nil {
		return "", nil, err
	}
	return cp, f, nil
}

// unlocksWith reports whether the entry id of the ring at path unlocks under pw.
func unlocksWith(path, id, pw string) bool {
	k, err := keystore.Open(path)
	if err != nil {
		return false
	}
	priv, err := k.ExportPrivate(id, []byte(pw))
	if err != nil {
		return false
	}
	clear(priv)
	return true
}

func ids(f *ringfile.File) []string {
	out := make([]string, 0, len(f.Entries))
	for _, e := range f.Entries {
		out = append(out, e.ID)
	}
	sort.Strings(out)
	return out
}

// debris lists everything in dir that is not the ring or its lock.
func debris(dir, ringName string) (tmps, other []string) {
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		n := e.Name()
		switch {
		case n == ringName || n == ringName+".lock":
		case strings.HasPrefix(n, "."+ringName+".") && strings.HasSuffix(n, ".tmp"):
			tmps = append(tmps, n)
		default:
			other = append(other, n)
		}
	}
	return
}

// results is appended to TOPO_OUT as one JSON object per line.
var outMu sync.Mutex

func record(name string, kv map[string]any) {
	kv["test"] = name
	kv["os"] = runtime.GOOS + "/" + runtime.GOARCH
	kv["ts"] = time.Now().UTC().Format(time.RFC3339)
	b, _ := json.Marshal(kv)
	if p := os.Getenv("TOPO_OUT"); p != "" {
		outMu.Lock()
		defer outMu.Unlock()
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			f.Write(append(b, '\n'))
			f.Close()
		}
	}
}

func parsePub(pem string) (ed25519.PublicKey, error) { return keystore.ParsePublicKeyPEM([]byte(pem)) }

func killProc(p *os.Process) { p.Signal(syscall.SIGKILL) }
