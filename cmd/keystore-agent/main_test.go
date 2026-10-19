package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode"

	"github.com/netstar-labs/keystore/internal/kdf"
	"github.com/netstar-labs/keystore/pkg/agent"
	"github.com/netstar-labs/keystore/pkg/keystore"
)

const pass = "agent test passphrase"

func TestMain(m *testing.M) {
	if os.Getenv("KEYSTORE_AGENT_RUN_MAIN") == "1" { // the test re-executes itself as the command
		main()
		return
	}
	kdf.Default = kdf.Cost{Mem: kdf.MinMem, Time: 1, Par: 1}
	os.Unsetenv("KEYSTORE_KEYCHAIN")
	os.Exit(m.Run())
}

func fixture(t *testing.T) (ring, sock string, pub ed25519.PublicKey) {
	t.Helper()
	ring = filepath.Join(t.TempDir(), "r.ks")
	k, _ := keystore.Create(ring)
	pub, _ = k.Add("prod", []byte(pass))
	dir, _ := os.MkdirTemp("/tmp", "kag")
	t.Cleanup(func() { os.RemoveAll(dir) })
	return ring, filepath.Join(dir, "a.sock"), pub
}

func waitFor(t *testing.T, sock string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(sock); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("agent socket never appeared")
}

func TestServesThenExpiresCleanly(t *testing.T) {
	ring, sock, pub := fixture(t)
	t.Setenv("KEYSTORE_PASSPHRASE", pass)
	done := make(chan error, 1)
	go func() { done <- run([]string{"-keystore", ring, "-sock", sock, "-ttl", "700ms"}) }()
	waitFor(t, sock)
	if v, ok := os.LookupEnv("KEYSTORE_PASSPHRASE"); ok {
		t.Fatalf("passphrase still in the environment: %q", v)
	}
	c, err := agent.Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := c.Sign(nil, []byte("m"), crypto.Hash(0))
	if err != nil || !ed25519.Verify(pub, []byte("m"), sig) {
		t.Fatalf("sign via agent: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("agent exit after ttl = %v, want nil (exit 0)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent outlived -ttl")
	}
	if _, err := os.Lstat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("socket left behind")
	}
}

func TestNeverPromptsNorReadsKeychain(t *testing.T) {
	ring, sock, _ := fixture(t)
	t.Setenv("KEYSTORE_PASSPHRASE", "")
	if err := run([]string{"-keystore", ring, "-sock", sock}); err == nil {
		t.Fatal("agent started with no passphrase source")
	}
	t.Setenv("KEYSTORE_PASSPHRASE", pass)
	t.Setenv("KEYSTORE_KEYCHAIN", "svc")
	if err := run([]string{"-keystore", ring, "-sock", sock}); err == nil {
		t.Fatal("agent accepted KEYSTORE_KEYCHAIN")
	}
}

func TestWrongPassphraseAndMissingFlags(t *testing.T) {
	ring, sock, _ := fixture(t)
	t.Setenv("KEYSTORE_PASSPHRASE", "not the passphrase")
	if err := run([]string{"-keystore", ring, "-sock", sock}); !errors.Is(err, keystore.ErrBadPass) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, err := os.Lstat(sock); err == nil {
		t.Fatal("socket created despite a failed unlock")
	}
	if err := run([]string{"-keystore", ring}); err == nil {
		t.Fatal("missing -sock accepted")
	}
}

// A negative -ttl or -idle must be refused before the passphrase is read, not run as
// "unlimited".
func TestNegativeLifetimeFlagsRefused(t *testing.T) {
	ring, sock, _ := fixture(t)
	for _, flagName := range []string{"-ttl", "-idle"} {
		err := run([]string{"-keystore", ring, "-sock", sock, flagName, "-1s"})
		if err == nil || !strings.Contains(err.Error(), "negative") {
			t.Errorf("%s -1s: err = %v, want a refusal naming a negative value", flagName, err)
		}
	}
}

// main prints errors and flag problems to the terminal: whatever an operator's script
// passed (a flag name, a ring path) must not be able to act on it or forge a line.
func TestMainOutputIsInert(t *testing.T) {
	const forged = "keystore: verified: SHA256:FORGED"
	for name, args := range map[string][]string{
		"unknown flag":   {"-a\n" + forged},
		"ring path":      {"-keystore", "/nonexistent/x\x1b[31m\r" + forged, "-sock", "/tmp/x.sock"},
		"unknown flag 2": {"-\x1b]0;t\x07\r" + forged},
	} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = append(os.Environ(), "KEYSTORE_AGENT_RUN_MAIN=1", "KEYSTORE_PASSPHRASE=")
			out, _ := cmd.CombinedOutput()
			for _, line := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(line, "keystore: verified") {
					t.Errorf("forged line in output: %q", out)
				}
			}
			for _, r := range string(out) {
				if r != '\n' && r != '\t' && !unicode.IsPrint(r) {
					t.Fatalf("terminal-active rune %U in output %q", r, out)
				}
			}
			if !strings.Contains(string(out), "keystore-agent:") {
				t.Errorf("no error line printed: %q", out)
			}
		})
	}
}

// The agent's own 'serving … on <socket>' log line echoes the -sock path; it must be inert
// too, and the usage text (now printed by our Usage func, not the flag package) must still
// follow a mistyped flag.
func TestServingLineAndUsageAreInertAndPresent(t *testing.T) {
	ring, sock, _ := fixture(t)
	hostileSock := filepath.Join(filepath.Dir(sock), "s\x1b]0;t\x07\rkeystore: verified: FORGED.sock")
	pf := filepath.Join(t.TempDir(), "pf")
	if err := os.WriteFile(pf, []byte(pass), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-keystore", ring, "-sock", hostileSock, "-passfile", pf, "-ttl", "1s", "-idle", "0")
	cmd.Env = append(os.Environ(), "KEYSTORE_AGENT_RUN_MAIN=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("agent: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "serving prod") {
		t.Fatalf("no serving line: %q", out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "keystore: verified: FORGED") && !strings.Contains(line, "serving") {
			t.Errorf("forged line %q", line)
		}
	}
	for _, r := range string(out) {
		if r != '\n' && r != '\t' && !unicode.IsPrint(r) {
			t.Fatalf("terminal-active rune %U in %q", r, out)
		}
	}

	cmd = exec.Command(os.Args[0], "-nosuchflag")
	cmd.Env = append(os.Environ(), "KEYSTORE_AGENT_RUN_MAIN=1")
	out, _ = cmd.CombinedOutput()
	if !strings.Contains(string(out), "Usage of keystore-agent:") || !strings.Contains(string(out), "-keystore") {
		t.Errorf("usage text missing after a mistyped flag: %q", out)
	}
}

// -h and -help are a request, not a mistake: usage on stderr, exit 0, no error line, as
// every `keystore <verb> -h` and the userguide's Exit status say.
func TestHelpFlagsExitZeroWithUsageOnly(t *testing.T) {
	for _, flagName := range []string{"-h", "-help"} {
		t.Run(flagName, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], flagName)
			cmd.Env = append(os.Environ(), "KEYSTORE_AGENT_RUN_MAIN=1")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				t.Errorf("%s: %v, want exit 0\n%s", flagName, err, stderr.String())
			}
			if !strings.Contains(stderr.String(), "Usage of keystore-agent:") || !strings.Contains(stderr.String(), "-keystore") {
				t.Errorf("%s: usage not on stderr: %q", flagName, stderr.String())
			}
			if strings.Contains(stderr.String(), "help requested") || strings.Contains(stderr.String(), "keystore-agent: flag") || stdout.Len() != 0 {
				t.Errorf("%s: error line or stdout output: stderr %q stdout %q", flagName, stderr.String(), stdout.String())
			}
		})
	}
}

// -h is the only parse error that is not a failure: an unknown flag still exits 1 with the
// usage and the (cleaned) flag error, so treating ErrHelp as success cannot swallow real errors.
func TestUnknownFlagStillFails(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-bogus")
	cmd.Env = append(os.Environ(), "KEYSTORE_AGENT_RUN_MAIN=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 {
		t.Fatalf("-bogus: %v, want exit 1\n%s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") || !strings.Contains(stderr.String(), "Usage of keystore-agent:") {
		t.Errorf("-bogus: stderr %q lacks the flag error or the usage", stderr.String())
	}
}

// SIGHUP is what a terminal-launched agent gets when its terminal closes. The agent has no
// reload, so it must stop exactly as it does on SIGINT/SIGTERM: socket removed, exit 0.
// Left to the default action it died with status 129 and the socket pointing at nothing.
func TestSignalsStopTheAgentCleanly(t *testing.T) {
	for name, s := range map[string]os.Signal{"SIGHUP": syscall.SIGHUP, "SIGTERM": syscall.SIGTERM, "SIGINT": os.Interrupt} {
		t.Run(name, func(t *testing.T) {
			if s == syscall.SIGHUP && signal.Ignored(syscall.SIGHUP) {
				// The child inherits the ignore (nohup, some CI) and the agent then honours it
				// (TestInheritedIgnoredSIGHUPIsHonoured), so it would not stop.
				t.Skip("SIGHUP is ignored in the test process; the agent child inherits that")
			}
			cmd, sock := startAgent(t, false)
			if err := cmd.Process.Signal(s); err != nil {
				t.Fatal(err)
			}
			if err := waitExit(t, cmd, name); err != nil {
				t.Fatalf("agent after %s: %v, want clean exit 0", name, err)
			}
			if _, err := os.Lstat(sock); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("socket left behind after %s", name)
			}
		})
	}
}

// An agent started under nohup (SIGHUP inherited as ignored) must keep ignoring it: Notify
// would silently replace the ignore with a handler, so the agent must not ask for it.
func TestInheritedIgnoredSIGHUPIsHonoured(t *testing.T) {
	cmd, sock := startAgent(t, true)
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // absence of a stop can only be observed by waiting
	if _, err := agent.Dial(sock); err != nil {
		t.Fatalf("agent not serving after an ignored SIGHUP: %v", err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitExit(t, cmd, "SIGTERM"); err != nil {
		t.Fatalf("agent after SIGTERM: %v, want clean exit 0", err)
	}
	if _, err := os.Lstat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("socket left behind after SIGTERM")
	}
}

// startAgent re-executes the test binary as keystore-agent and returns once it is serving.
// A successful Dial fetches the public key through Serve, which only starts after the signal
// handlers are installed, so a signal sent after startAgent returns cannot race them.
// ignoreHUP starts it the way nohup does: through a shell that sets SIGHUP to ignored.
func startAgent(t *testing.T, ignoreHUP bool) (*exec.Cmd, string) {
	t.Helper()
	ring, sock, _ := fixture(t)
	pf := filepath.Join(t.TempDir(), "pf")
	if err := os.WriteFile(pf, []byte(pass), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-keystore", ring, "-sock", sock, "-passfile", pf}
	cmd := exec.Command(os.Args[0], args...)
	if ignoreHUP {
		cmd = exec.Command("sh", append([]string{"-c", `trap "" HUP; exec "$0" "$@"`, os.Args[0]}, args...)...)
	}
	cmd.Env = append(os.Environ(), "KEYSTORE_AGENT_RUN_MAIN=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	waitFor(t, sock)
	for i := 0; ; i++ {
		_, err := agent.Dial(sock)
		if err == nil {
			return cmd, sock
		}
		if i == 200 {
			t.Fatalf("agent never answered: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitExit(t *testing.T, cmd *exec.Cmd, what string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("agent ignored %s", what)
		return nil
	}
}

// The 'socket was removed or replaced' line quotes the socket path from inside pkg/agent,
// which cannot know the path came from an operator. The command's log sink must clean it:
// a directory named with ESC and CR otherwise reaches the terminal raw.
func TestSocketLostLogLineIsInert(t *testing.T) {
	ring, _, _ := fixture(t)
	base, err := os.MkdirTemp("/tmp", "kag")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	dir := filepath.Join(base, "d\x1b[31m\rkeystore: FORGED\nFORGEDLINE: agent compromised")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "a.sock")
	pf := filepath.Join(t.TempDir(), "pf")
	if err := os.WriteFile(pf, []byte(pass), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-keystore", ring, "-sock", sock, "-passfile", pf)
	cmd.Env = append(os.Environ(), "KEYSTORE_AGENT_RUN_MAIN=1")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	waitFor(t, sock)
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select { // the agent notices a lost socket on a 10 s check
	case err := <-done:
		if err == nil {
			t.Fatal("agent exited 0 after its socket was removed, want 1")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("agent did not stop after its socket was removed")
	}
	if !strings.Contains(out.String(), "was removed or replaced") {
		t.Fatalf("no socket-lost line: %q", out.String())
	}
	for _, r := range out.String() {
		if r != '\n' && !unicode.IsPrint(r) {
			t.Fatalf("terminal-active rune %U in %q", r, out.String())
		}
	}
	// A newline in the operator-supplied path must not start a forged line of its own.
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, "FORGEDLINE") {
			t.Fatalf("a path forged a log line: %q", out.String())
		}
	}
}
