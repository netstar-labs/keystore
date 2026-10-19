//go:build integration

// Package livetest is the shared scaffolding of the live-integration tier (audit L3): the
// opt-in guard, a way to get the keystore binaries, and a clean-environment runner. It
// exists only under the integration build tag, so the default build never sees it.
package livetest

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// RequireLive skips the calling test unless KEYSTORE_LIVE=1, and under -short. This is the
// second of the tier's two opt-ins (the first is the build tag).
func RequireLive(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("live-integration tier: refused under -short")
	}
	if os.Getenv("KEYSTORE_LIVE") != "1" {
		t.Skip("live-integration tier: set KEYSTORE_LIVE=1 to run")
	}
}

// ModuleRoot returns the directory holding go.mod, found by walking up from the test's
// working directory.
func ModuleRoot(t *testing.T) string {
	t.Helper()
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		p := filepath.Dir(d)
		if p == d {
			t.Fatal("no go.mod above the test's working directory")
		}
		d = p
	}
}

// Binaries returns a directory holding keystore and keystore-agent. KEYSTORE_BIN names a
// prebuilt directory (the container runner sets it: there is no Go toolchain in the
// image); otherwise both are built from this module into a temp dir. A missing toolchain
// is an environment problem and skips; a build error is the module's and fails.
func Binaries(t *testing.T) string {
	t.Helper()
	if d := os.Getenv("KEYSTORE_BIN"); d != "" {
		return d
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on PATH and KEYSTORE_BIN unset: cannot obtain the keystore binaries")
	}
	dir := t.TempDir()
	cmd := exec.Command(goBin, "build", "-o", dir+string(filepath.Separator), "./cmd/keystore", "./cmd/keystore-agent")
	cmd.Dir = ModuleRoot(t)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build keystore: %v\n%s", err, out)
	}
	return dir
}

// Result is one finished process.
type Result struct {
	Stdout, Stderr string
	Exit           int
}

// Run executes bin with a minimal environment (PATH, HOME and TMPDIR only, plus extra), so
// nothing the developer has exported (KEYSTORE_PASSPHRASE, KEYSTORE_FILE, a keychain
// service) can leak into the system under test. A process that cannot be started at all
// fails the test; a nonzero exit is returned for the caller to judge.
func Run(t *testing.T, bin string, home string, stdin []byte, extra []string, args ...string) Result {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "TMPDIR=" + os.TempDir()}, extra...)
	cmd.Stdin = bytes.NewReader(stdin)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	r := Result{Stdout: so.String(), Stderr: se.String()}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		r.Exit = ee.ExitCode()
	default:
		t.Fatalf("%s %v: %v", bin, args, err)
	}
	return r
}
