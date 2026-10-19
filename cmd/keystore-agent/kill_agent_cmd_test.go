package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/netstar-labs/keystore/pkg/agent"
	"github.com/netstar-labs/keystore/pkg/keystore"
)

// twoKeys makes a ring with keys "first" (current) and "second", returning both public keys.
func twoKeys(t *testing.T) (ring, sock string, first, second ed25519.PublicKey) {
	t.Helper()
	ring, sock, first = fixture(t) // fixture's key is "prod"
	k, err := keystore.Open(ring)
	if err != nil {
		t.Fatal(err)
	}
	second, err = k.Add("second", []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	return ring, sock, first, second
}

// -id selects which ring key the agent serves; without it, the current one.
func TestAgentServesTheKeyNamedByID(t *testing.T) {
	ring, sock, first, second := twoKeys(t)
	t.Setenv("KEYSTORE_PASSPHRASE", pass)
	done := make(chan error, 1)
	go func() {
		done <- run([]string{"-keystore", ring, "-sock", sock, "-id", "second", "-ttl", "0", "-idle", "500ms"})
	}()
	waitFor(t, sock)
	c, err := agent.Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Public().(ed25519.PublicKey); got.Equal(first) || !got.Equal(second) {
		t.Fatalf("agent serves %x, want the key named by -id (%x), not the current one (%x)", got, second, first)
	}
	if err := <-done; err != nil {
		t.Fatalf("agent exit after idle = %v, want nil", err)
	}
}

// -ttl and -idle are not interchangeable: -ttl 0 means no overall limit, so a client that
// keeps using the agent keeps it alive past any idle window, and silence ends it.
func TestAgentIdleIsNotTTL(t *testing.T) {
	ring, sock, _, _ := twoKeys(t)
	t.Setenv("KEYSTORE_PASSPHRASE", pass)
	done := make(chan error, 1)
	go func() { done <- run([]string{"-keystore", ring, "-sock", sock, "-ttl", "0", "-idle", "1500ms"}) }()
	waitFor(t, sock)
	c, err := agent.Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ { // 3 s of use: two idle windows
		time.Sleep(250 * time.Millisecond)
		if _, err := c.Sign(nil, []byte("keepalive"), crypto.Hash(0)); err != nil {
			t.Fatalf("agent went away while in use (-ttl 0 must mean no overall limit): %v", err)
		}
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("exit = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not stop after going idle")
	}
}

// A relative -sock is made absolute, so the "serving ... on" line names where the socket
// really is whatever directory the operator started the agent from.
func TestAgentLogsTheAbsoluteSocketPath(t *testing.T) {
	ring, sock, _ := fixture(t)
	pf := filepath.Join(t.TempDir(), "pf")
	if err := os.WriteFile(pf, []byte(pass), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-keystore", ring, "-sock", filepath.Base(sock), "-passfile", pf, "-ttl", "1s", "-idle", "0")
	cmd.Dir = filepath.Dir(sock)
	cmd.Env = append(os.Environ(), "KEYSTORE_AGENT_RUN_MAIN=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("agent: %v\n%s", err, out)
	}
	dir, _ := filepath.EvalSymlinks(filepath.Dir(sock))
	if !strings.Contains(string(out), " on "+sock+";") && !strings.Contains(string(out), " on "+filepath.Join(dir, filepath.Base(sock))+";") {
		t.Fatalf("serving line does not name the absolute socket path %s:\n%s", sock, out)
	}
}

func TestAgentRequiresSockAndRingAsUsageErrors(t *testing.T) {
	ring, sock, _ := fixture(t)
	t.Setenv("KEYSTORE_PASSPHRASE", pass)
	if err := run([]string{"-keystore", ring}); err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("no -sock: %v, want the 'required' usage error", err)
	}
	if err := run([]string{"-sock", sock}); err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("no -keystore: %v, want the 'required' usage error", err)
	}
	if err := run([]string{"-keystore", ring, "-sock", sock, "stray"}); err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("stray argument: %v, want the usage error", err)
	}
}

// Run as the real command: the defaults are 8h and 30m, rejected requests are logged,
// SIGTERM stops it cleanly (exit 0, socket removed) and says so.
func TestAgentCommandDefaultsLoggingAndSIGTERM(t *testing.T) {
	ring, sock, _ := fixture(t)
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
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { cmd.Process.Kill() })
	waitFor(t, sock)

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	hdr := []byte{agent.OpSign, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(hdr[1:], agent.MaxPayload+1)
	conn.Write(hdr)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	conn.Read(make([]byte, 64)) // the error reply: by the time it arrives the line is logged
	conn.Close()

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("agent exit after SIGTERM = %v\n%s", err, out.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("agent ignored SIGTERM\n%s", out.String())
	}
	log := out.String()
	for _, want := range []string{"ttl 8h0m0s, idle 30m0s", "rejected oversize frame", "stopping"} {
		if !strings.Contains(log, want) {
			t.Errorf("agent log lacks %q:\n%s", want, log)
		}
	}
	if _, err := os.Lstat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket left behind after SIGTERM: %v", err)
	}
}
