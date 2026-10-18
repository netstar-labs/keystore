package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netstar-labs/keystore/internal/kdf"
	"github.com/netstar-labs/keystore/pkg/keystore"
)

const pass = "secrets example passphrase"

func TestMain(m *testing.M) {
	kdf.Default = kdf.Cost{Mem: kdf.MinMem, Time: 1, Par: 1}
	os.Exit(m.Run())
}

func fixture(t *testing.T) (ring, pf string, key []byte) {
	t.Helper()
	dir := t.TempDir()
	ring = filepath.Join(dir, "r.ks")
	k, _ := keystore.Create(ring)
	key = []byte("example-hmac-key-0123456789abcdef")
	if err := k.ImportSecret("hmac", key, []byte(pass)); err != nil {
		t.Fatal(err)
	}
	pf = filepath.Join(dir, "pass")
	os.WriteFile(pf, []byte(pass+"\n"), 0o600)
	return ring, pf, key
}

func TestTagMatchesHMAC(t *testing.T) {
	ring, pf, key := fixture(t)
	var out bytes.Buffer
	if err := run(ring, "hmac", pf, "hello", &out); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(out.String()), hex.EncodeToString(Tag(key, []byte("hello"))); got != want {
		t.Fatalf("tag %s, want %s", got, want)
	}
	// RFC 4231 test case 2, so Tag itself is pinned to a published vector.
	if hex.EncodeToString(Tag([]byte("Jefe"), []byte("what do ya want for nothing?"))) !=
		"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" {
		t.Fatal("Tag does not match RFC 4231")
	}
}

func TestWrongPassphraseAndMissingSecret(t *testing.T) {
	ring, pf, _ := fixture(t)
	bad := filepath.Join(t.TempDir(), "bad")
	os.WriteFile(bad, []byte("not the passphrase"), 0o600)
	if err := run(ring, "hmac", bad, "m", &bytes.Buffer{}); !errors.Is(err, keystore.ErrBadPass) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if err := run(ring, "nope", pf, "m", &bytes.Buffer{}); !errors.Is(err, keystore.ErrNoKey) {
		t.Fatalf("missing secret: %v", err)
	}
	loose := filepath.Join(t.TempDir(), "loose")
	os.WriteFile(loose, []byte(pass), 0o644)
	if err := run(ring, "hmac", loose, "m", &bytes.Buffer{}); err == nil {
		t.Fatal("world-readable passfile accepted")
	}
}

// A ring entry modified on disk must not yield a (wrong) secret.
func TestTamperedSecretRefused(t *testing.T) {
	ring, pf, _ := fixture(t)
	raw, _ := os.ReadFile(ring)
	i := bytes.Index(raw, []byte(`"ct": "`)) + len(`"ct": "`)
	raw[i+4] ^= 'A' ^ 'B'
	if raw[i+4] == '"' {
		t.Skip("unlucky byte")
	}
	os.WriteFile(ring, raw, 0o600)
	if err := run(ring, "hmac", pf, "m", &bytes.Buffer{}); err == nil {
		t.Fatal("tampered secret accepted")
	}
}
