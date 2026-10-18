package main

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netstar-labs/keystore/internal/kdf"
	"github.com/netstar-labs/keystore/pkg/agent"
	"github.com/netstar-labs/keystore/pkg/keystore"
)

const pass = "agent test passphrase"

func TestMain(m *testing.M) {
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
