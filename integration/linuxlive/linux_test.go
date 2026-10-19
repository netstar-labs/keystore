//go:build integration && linux

// Package linuxlive holds the checks that only mean something on a real Linux kernel and
// filesystem: file modes, flock, and SO_PEERCRED across two real uids. The container
// runner compiles it for linux/arm64 and runs it as root and as uid 1000.
package linuxlive

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/netstar-labs/keystore/integration/internal/livetest"
	"golang.org/x/sys/unix"
)

type env struct{ *livetest.Env }

func setup(t *testing.T) *env {
	t.Helper()
	livetest.RequireLive(t)
	return &env{livetest.NewEnv(t)}
}

func (e *env) ks(args ...string) livetest.Result { return e.KS(nil, args...) }

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// Modes under a hostile umask: files keystore creates must not depend on it being sane.
func TestFileModes(t *testing.T) {
	e := setup(t)
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })
	pf := e.Passfile()
	ring := filepath.Join(e.Dir, "ring.ks")
	if r := e.ks("keygen", "-keystore", ring, "-passfile", pf, "-id", "k"); r.Exit != 0 {
		t.Fatalf("keygen: %s", r.Stderr)
	}
	if m := mode(t, ring); m != 0o600 {
		t.Errorf("ring mode %o, want 600 (umask 000)", m)
	}
	priv := filepath.Join(e.Dir, "k.priv")
	if r := e.ks("export-priv", "-keystore", ring, "-passfile", pf, "-id", "k", "-o", priv); r.Exit != 0 {
		t.Fatalf("export-priv: %s", r.Stderr)
	}
	if m := mode(t, priv); m != 0o600 {
		t.Errorf("exported private key mode %o, want 600", m)
	}
	// The default ring lives in an owner-only directory it creates.
	if r := e.ks("init"); r.Exit != 0 {
		t.Fatalf("init (default ring): %s", r.Stderr)
	}
	if m := mode(t, filepath.Join(e.Dir, ".config", "keystore")); m != 0o700 {
		t.Errorf("default ring directory mode %o, want 700", m)
	}
	if m := mode(t, filepath.Join(e.Dir, ".config", "keystore", "default.ks")); m != 0o600 {
		t.Errorf("default ring mode %o, want 600", m)
	}
	// A group-readable
	// passfile must be refused.
	if err := os.Chmod(pf, 0o640); err != nil {
		t.Fatal(err)
	}
	if r := e.ks("add", "-keystore", ring, "-passfile", pf, "-id", "k2"); r.Exit == 0 {
		t.Errorf("a 0640 passfile was accepted")
	}
}

func fsName(p string) string {
	var s unix.Statfs_t
	if err := unix.Statfs(p, &s); err != nil {
		return err.Error()
	}
	return fmt.Sprintf("0x%x", s.Type)
}

// flock on the container's filesystems: a held ring lock must block writers until
// LockTimeout (10 s) and then release cleanly; verbs that only read must not take it.
func TestRingFlockContention(t *testing.T) {
	e := setup(t)
	pf := e.Passfile()
	for _, dir := range []string{e.Dir, "/dev/shm"} {
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			continue
		}
		d, err := os.MkdirTemp(dir, "kf-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(d)
		t.Logf("flock on %s (statfs type %s)", dir, fsName(d))
		ring := filepath.Join(d, "r.ks")
		if r := e.ks("keygen", "-keystore", ring, "-passfile", pf, "-id", "k"); r.Exit != 0 {
			t.Fatalf("keygen: %s", r.Stderr)
		}
		lock, err := os.OpenFile(ring+".lock", os.O_RDWR, 0)
		if err != nil {
			t.Fatalf("lock sidecar missing: %v", err)
		}
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatalf("test could not take the lock: %v", err)
		}
		start := time.Now()
		r := e.ks("add", "-keystore", ring, "-passfile", pf, "-id", "blocked")
		waited := time.Since(start)
		if r.Exit == 0 || !strings.Contains(r.Stderr, "locked") {
			t.Errorf("%s: add while the lock was held: exit %d, stderr %q", dir, r.Exit, r.Stderr)
		}
		if waited < 8*time.Second || waited > 20*time.Second {
			t.Errorf("%s: add gave up after %v, want about LockTimeout (10 s)", dir, waited)
		}
		if r := e.ks("list", "-keystore", ring); r.Exit != 0 {
			t.Errorf("%s: list must not need the lock: %s", dir, r.Stderr)
		}
		syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		lock.Close()
		if r := e.ks("add", "-keystore", ring, "-passfile", pf, "-id", "after"); r.Exit != 0 {
			t.Errorf("%s: add after release: %s", dir, r.Stderr)
		}
	}
}

func startAgent(e *env, uid int, dir string) (sock string, stop func()) {
	t := e.T
	ring := filepath.Join(dir, "r.ks")
	pf := filepath.Join(dir, "pf")
	sock = filepath.Join(dir, "a.sock")
	cmd := exec.Command(filepath.Join(e.Bin, "keystore-agent"), "-keystore", ring, "-sock", sock, "-passfile", pf, "-ttl", "2m", "-idle", "0")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir}
	if uid != os.Getuid() {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(uid)}}
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stop = func() { cmd.Process.Kill(); cmd.Wait() }
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(sock); err == nil {
			return sock, stop
		}
		time.Sleep(50 * time.Millisecond)
	}
	stop()
	t.Fatalf("agent socket never appeared: %s", stderr.String())
	return "", nil
}

// SO_PEERCRED on the real kernel: the same-uid happy path always; and, as root, an agent
// owned by uid 1000 must be refused by the root client, and a root connection must be
// dropped by the uid-1000 server, although root can open the socket (mode bits do not
// stop root, so only the peer-uid check can).
func TestPeerCredAcrossUIDs(t *testing.T) {
	e := setup(t)
	uid := os.Getuid()
	dir, err := os.MkdirTemp("", "ka-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	os.Chmod(dir, 0o700)
	pfPath := filepath.Join(dir, "pf")
	os.WriteFile(pfPath, []byte(livetest.Passphrase+"\n"), 0o600)
	ring := filepath.Join(dir, "r.ks")
	if r := livetest.Run(t, filepath.Join(e.Bin, "keystore"), dir, nil, nil, "keygen", "-keystore", ring, "-passfile", pfPath, "-id", "k"); r.Exit != 0 {
		t.Fatalf("keygen: %s", r.Stderr)
	}

	// Same uid: signs through the agent.
	sock, stop := startAgent(e, uid, dir)
	if m := mode(t, sock); m != 0o600 {
		t.Errorf("agent socket mode %o, want 600", m)
	}
	msg := filepath.Join(dir, "m")
	os.WriteFile(msg, []byte("x"), 0o600)
	if r := livetest.Run(t, filepath.Join(e.Bin, "keystore"), dir, nil, nil, "sign", "-agent", sock, "-in", msg); r.Exit != 0 {
		t.Errorf("same-uid sign through the agent failed: %s", r.Stderr)
	}
	stop()
	os.Remove(sock)
	os.Remove(sock + ".lock") // root's lock file would stop the uid-1000 agent from opening it

	if uid != 0 {
		t.Skip("same-uid half passed; the cross-uid half needs root (the root leg runs it)")
	}
	const other = 1000
	for _, p := range []string{dir, ring, pfPath} {
		if err := os.Chown(p, other, other); err != nil {
			t.Fatal(err)
		}
	}
	sock, stop = startAgent(e, other, dir)
	defer stop()
	// Root reaches the socket (root ignores mode bits) ...
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("root could not connect, so the peer-uid check is not what is being tested: %v", err)
	}
	defer conn.Close()
	// ... server side: the uid-1000 agent must drop the root peer without answering.
	conn.Write([]byte{'P', 0, 0, 0, 0})
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	if n, err := conn.Read(buf); n != 0 || err == nil {
		t.Errorf("agent answered a root peer: %d bytes %x", n, buf[:n])
	}
	// ... client side: the root client must refuse the uid-1000 agent.
	r := livetest.Run(t, filepath.Join(e.Bin, "keystore"), dir, nil, nil, "sign", "-agent", sock, "-in", msg)
	if r.Exit == 0 || !strings.Contains(r.Stderr, "served by uid 1000") {
		t.Errorf("root client signed through a uid-1000 agent or refused for the wrong reason: exit %d %q", r.Exit, r.Stderr)
	}
}
