//go:build integration && darwin

// Package keychain is the opt-in live test of the macOS login keychain through the real
// /usr/bin/security. It is NOT run by the audit: the owner has not confirmed writes to
// their keychain. It needs the build tag, KEYSTORE_LIVE=1 and KEYSTORE_LIVE_KEYCHAIN=1,
// uses a unique throwaway service name (never the real "keystore" item), and deletes what
// it created in t.Cleanup. macOS may show an access prompt; in a headless session the
// calls fail and the test skips.
package keychain

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/netstar-labs/keystore/integration/internal/livetest"
	"github.com/netstar-labs/keystore/internal/keychain"
)

const security = "/usr/bin/security"

func TestLoginKeychainRoundTrip(t *testing.T) {
	livetest.RequireLive(t)
	if os.Getenv("KEYSTORE_LIVE_KEYCHAIN") != "1" {
		t.Skip("set KEYSTORE_LIVE_KEYCHAIN=1 to write one throwaway item to your login keychain")
	}
	var b [8]byte
	rand.Read(b[:])
	// Never the real "keystore" item: the prefix plus 64 random bits cannot collide with it.
	svc := "keystore-l3-throwaway-" + hex.EncodeToString(b[:])
	const secret = "l3 throwaway passphrase"

	t.Cleanup(func() { exec.Command(security, "delete-generic-password", "-s", svc, "-a", keychain.Account).Run() })
	if out, err := exec.Command(security, "add-generic-password", "-s", svc, "-a", keychain.Account, "-w", secret).CombinedOutput(); err != nil {
		t.Skipf("cannot write to the login keychain here (locked, headless or prompt denied): %v: %s", err, out)
	}
	got, err := keychain.Get(svc)
	if err != nil || string(got) != secret {
		t.Fatalf("Get(%s) = %q, %v; want the stored secret", svc, got, err)
	}
	// Known-bad: a service that was never created is "not found".
	if _, err := keychain.Get(svc + "-absent"); !errors.Is(err, keychain.ErrNotFound) {
		t.Fatalf("absent service: err = %v, want ErrNotFound", err)
	}

	// End to end: a ring whose passphrase lives in the keychain unlocks with no passfile.
	bin := livetest.Binaries(t)
	dir := t.TempDir()
	pf := filepath.Join(dir, "pf")
	os.WriteFile(pf, []byte(secret+"\n"), 0o600)
	ring := filepath.Join(dir, "r.ks")
	ks := filepath.Join(bin, "keystore")
	if r := livetest.Run(t, ks, dir, nil, nil, "keygen", "-keystore", ring, "-passfile", pf, "-id", "k"); r.Exit != 0 {
		t.Fatalf("keygen: %s", r.Stderr)
	}
	// The real HOME, not a temp one: security locates the login keychain through it. (Never
	// executed by the audit, so whether this is enough is untried; see untestable-without-x.md.)
	r := livetest.Run(t, ks, os.Getenv("HOME"), []byte("msg"), []string{"KEYSTORE_KEYCHAIN=" + svc}, "sign", "-keystore", ring)
	if r.Exit != 0 {
		t.Fatalf("sign with the passphrase from the keychain: exit %d: %s", r.Exit, r.Stderr)
	}

	// Cleanup must really remove it.
	exec.Command(security, "delete-generic-password", "-s", svc, "-a", keychain.Account).Run()
	if _, err := keychain.Get(svc); !errors.Is(err, keychain.ErrNotFound) {
		t.Fatalf("item still present after delete: %v", err)
	}
}
