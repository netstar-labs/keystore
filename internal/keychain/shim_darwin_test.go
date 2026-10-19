package keychain

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// These tests never run /usr/bin/security: useShim points the package at a script in a
// temp dir that records how it was called.

const shimScript = `#!/bin/sh
d=$(dirname "$0")
printf '%s\n' "$@" > "$d/argv"
env > "$d/env"
cat > "$d/stdin"
[ -f "$d/stdout" ] && cat "$d/stdout"
code=0
[ -f "$d/exit" ] && code=$(cat "$d/exit")
exit "$code"
`

type shim struct{ dir string }

func useShim(t *testing.T) shim {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "security")
	if err := os.WriteFile(path, []byte(shimScript), 0o700); err != nil {
		t.Fatal(err)
	}
	old := security
	security = path
	t.Cleanup(func() { security = old })
	return shim{dir}
}

func (s shim) configure(t *testing.T, stdout string, exit int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(s.dir, "stdout"), []byte(stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, "exit"), []byte(strconv.Itoa(exit)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (s shim) read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.dir, name))
	if err != nil {
		t.Fatalf("shim did not record %s: %v", name, err)
	}
	return string(b)
}

func (s shim) ran() bool {
	_, err := os.Stat(filepath.Join(s.dir, "argv"))
	return err == nil
}

func TestRealSecurityIsTheDefault(t *testing.T) {
	if security != "/usr/bin/security" {
		t.Fatalf("security = %q: the binary is run by absolute path, never via PATH", security)
	}
}

func TestGetRunsExactArgv(t *testing.T) {
	sh := useShim(t)
	sh.configure(t, "hunter2\n", 0)
	got, err := Get("my-svc")
	if err != nil || string(got) != "hunter2" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	if want := "find-generic-password\n-s\nmy-svc\n-a\nkeystore\n-w\n"; sh.read(t, "argv") != want {
		t.Fatalf("argv = %q, want %q", sh.read(t, "argv"), want)
	}
}

// Only one trailing newline is security's framing; anything else is the secret.
func TestGetTrimsOnlyTheTrailingNewline(t *testing.T) {
	for _, tc := range []struct{ out, want string }{
		{"pw\n", "pw"}, {"pw", "pw"}, {"pw\n\n", "pw\n"}, {"p w\r\n", "p w\r"}, {"\n", ""}, {"", ""},
	} {
		sh := useShim(t)
		sh.configure(t, tc.out, 0)
		got, err := Get("svc")
		if err != nil || string(got) != tc.want {
			t.Errorf("output %q: Get = %q, %v; want %q", tc.out, got, err, tc.want)
		}
	}
}

// OBSERVATION, pinned on purpose: every failure of `security find-generic-password` is
// reported as ErrNotFound, including 36 (keychain locked / access denied) where "no
// keychain item" is misleading; only 44 means not found. If this test fails because the
// mapping was fixed, update it as a conscious change.
func TestGetMapsEveryFailureToErrNotFoundCurrentBehaviour(t *testing.T) {
	for _, code := range []int{44, 36, 51, 128, 1} {
		sh := useShim(t)
		sh.configure(t, "partial-output\n", code)
		got, err := Get("svc")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("exit %d: err = %v, want ErrNotFound (current behaviour)", code, err)
		}
		if got != nil {
			t.Errorf("exit %d: returned %q alongside an error", code, got)
		}
	}
}

func TestSetRunsExactArgvAndKeepsSecretOutOfArgvAndEnv(t *testing.T) {
	const secret = "s3cr3t-passphrase-Zq9"
	sh := useShim(t)
	sh.configure(t, "", 0)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString(secret + "\n")
	w.Close()
	oldIn := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldIn; r.Close() }()

	if err := Set("my-svc"); err != nil {
		t.Fatal(err)
	}
	if want := "add-generic-password\n-s\nmy-svc\n-a\nkeystore\n-U\n-w\n"; sh.read(t, "argv") != want {
		t.Fatalf("argv = %q, want %q", sh.read(t, "argv"), want)
	}
	if got := sh.read(t, "stdin"); got != secret+"\n" {
		t.Fatalf("security's stdin = %q: Set must hand it the caller's stdin untouched", got)
	}
	for _, name := range []string{"argv", "env"} {
		if strings.Contains(sh.read(t, name), secret) {
			t.Errorf("passphrase appeared in the %s of the security process", name)
		}
	}
}

func TestSetFailureCarriesItsExitCode(t *testing.T) {
	sh := useShim(t)
	sh.configure(t, "", 45)
	err := Set("svc")
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 45 {
		t.Fatalf("Set = %v, want an *exec.ExitError with code 45", err)
	}
}

func TestBadServiceNeverExecs(t *testing.T) {
	sh := useShim(t)
	for _, s := range []string{"", "-w", "--help", "a b", "x;y", "a/b", "$(touch x)"} {
		if _, err := Get(s); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%q) = %v, want a validation error", s, err)
		}
		if err := Set(s); err == nil {
			t.Errorf("Set(%q) accepted", s)
		}
	}
	if sh.ran() {
		t.Fatal("security was executed for an invalid service name")
	}
}

func TestMissingBinary(t *testing.T) {
	old := security
	security = filepath.Join(t.TempDir(), "no-such-security")
	defer func() { security = old }()

	err := Set("svc")
	if !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "no-such-security") {
		t.Fatalf("Set = %v, want an error naming the missing binary", err)
	}
	// OBSERVATION, pinned: Get cannot tell a missing binary from a missing item.
	if _, err := Get("svc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get = %v, want ErrNotFound (current behaviour)", err)
	}
}
