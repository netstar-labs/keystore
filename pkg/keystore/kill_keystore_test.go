package keystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/netstar-labs/keystore/internal/ringfile"
)

// signingEntry builds a ring entry for a fresh Ed25519 key under id, encrypted with pw.
func signingEntry(t *testing.T, id string, pw []byte) ringfile.Entry {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	e, err := encrypt(id, ringfile.KindEd25519, spki, pkcs8, pw)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func secretEntry(t *testing.T, id string, pw []byte) ringfile.Entry {
	t.Helper()
	e, err := encrypt(id, ringfile.KindSecret, nil, []byte("a secret value"), pw)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func ringOf(t *testing.T, current string, es ...ringfile.Entry) (*Keystore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "r.ks")
	if err := ringfile.Create(path, &ringfile.File{Current: current, Entries: es}); err != nil {
		t.Fatal(err)
	}
	k, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return k, path
}

// A ring is meant to have one passphrase, but a file can be assembled by hand (or by an
// attacker with write access) from entries sealed under different ones. The two guards
// must then judge by the documented entry: add checks the FIRST entry, and passwd must
// unlock EVERY entry before it writes anything.
func TestMixedPassphraseRing(t *testing.T) {
	passA, passB := []byte("first entry passphrase"), []byte("second entry passphrase")
	newPass := []byte("a third passphrase here")
	build := func(t *testing.T) (*Keystore, string) {
		return ringOf(t, "a", signingEntry(t, "a", passA), secretEntry(t, "b", passB))
	}

	t.Run("add checks the first entry", func(t *testing.T) {
		k, _ := build(t)
		if _, err := k.Add("c", passB); !errors.Is(err, ErrPassphraseMismatch) {
			t.Fatalf("Add under the second entry's passphrase = %v, want ErrPassphraseMismatch", err)
		}
		if _, err := k.Add("c", passA); err != nil {
			t.Fatalf("Add under the first entry's passphrase: %v", err)
		}
	})

	for name, old := range map[string][]byte{"old unlocks only the first": passA, "old unlocks only the last": passB} {
		t.Run("passwd "+name, func(t *testing.T) {
			k, path := build(t)
			before, _ := os.ReadFile(path)
			if err := k.ChangePassphrase(old, newPass); !errors.Is(err, ErrBadPass) {
				t.Fatalf("ChangePassphrase = %v, want ErrBadPass", err)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("passwd rewrote a ring it could not fully unlock")
			}
			if _, err := k.Signer("a", passA); err != nil {
				t.Fatalf("entry a no longer opens under its passphrase: %v", err)
			}
			if _, err := k.Secret("b", passB); err != nil {
				t.Fatalf("entry b no longer opens under its passphrase: %v", err)
			}
		})
	}
}

// ExportPrivate's second check: the key inside the ciphertext must be the key the entry
// advertises. The AEAD binds the advertised key (it is in the AAD) but cannot know that
// the plaintext belongs to it; an entry sealed by a buggy or hostile writer can disagree.
func TestExportPrivateRefusesAnEntryWhoseKeyIsNotTheAdvertisedOne(t *testing.T) {
	pw := []byte("some passphrase here")
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	_, privB, _ := ed25519.GenerateKey(rand.Reader)
	spkiA, _ := x509.MarshalPKIXPublicKey(pubA)
	pkcs8B, _ := x509.MarshalPKCS8PrivateKey(privB)
	e, err := encrypt("k", ringfile.KindEd25519, spkiA, pkcs8B, pw) // A advertised, B inside
	if err != nil {
		t.Fatal(err)
	}
	k, _ := ringOf(t, "k", e)
	if priv, err := k.ExportPrivate("k", pw); !errors.Is(err, ErrBadFormat) || priv != nil {
		t.Fatalf("ExportPrivate = %v, %v; want nil, ErrBadFormat", priv, err)
	}
	if _, err := k.Signer("", pw); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("Signer = %v; want ErrBadFormat", err)
	}

	// Same length, one byte different: a length-only comparison would let it through.
	pubC, privC, _ := ed25519.GenerateKey(rand.Reader)
	spkiC, _ := x509.MarshalPKIXPublicKey(pubC)
	pkcs8C, _ := x509.MarshalPKCS8PrivateKey(privC)
	spkiC2 := append([]byte(nil), spkiC...)
	spkiC2[len(spkiC2)-1] ^= 1
	e2, err := encrypt("k", ringfile.KindEd25519, spkiC2, pkcs8C, pw)
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := ringOf(t, "k", e2)
	if _, err := k2.ExportPrivate("k", pw); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("ExportPrivate with a one-byte-different advertised key = %v, want ErrBadFormat", err)
	}
}

// Removing the current key hands "current" to the first remaining SIGNING key, never to a
// secret that happens to come first (which would also make the ring unwritable).
func TestRemoveCurrentPicksTheFirstRemainingSigningKey(t *testing.T) {
	pw := []byte("some passphrase here")
	k, path := ringOf(t, "a", signingEntry(t, "a", pw), secretEntry(t, "s", pw), signingEntry(t, "b", pw), signingEntry(t, "c", pw))
	if err := k.Remove("a", false); err != nil {
		t.Fatalf("Remove(current) = %v", err)
	}
	if got := k.CurrentID(); got != "b" {
		t.Fatalf("current after removing a = %q, want b (first remaining signing key)", got)
	}
	k2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if k2.CurrentID() != "b" {
		t.Fatalf("persisted current = %q, want b", k2.CurrentID())
	}
}

// Import must refuse anything that is not a full 64-byte Ed25519 private key with an
// error, not a panic from slicing a short one.
func TestImportRefusesWrongSizedKeys(t *testing.T) {
	k, _ := newRing(t)
	_, good, _ := ed25519.GenerateKey(rand.Reader)
	for _, n := range []int{0, 1, 31, 32, 63, 65, 128} {
		key := make(ed25519.PrivateKey, n)
		copy(key, good)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Import of a %d-byte key panicked: %v", n, r)
				}
			}()
			if err := k.Import("x", key, pass); err == nil {
				t.Errorf("Import accepted a %d-byte key", n)
			}
		}()
	}
	if len(k.List()) != 0 {
		t.Fatal("a refused import left an entry behind")
	}
}

// ParsePublicKeyPEM returns an Ed25519 key or an error; a well-formed SPKI for another
// algorithm must not come back as (nil, nil), which ed25519.Verify would then panic on.
func TestParsePublicKeyPEMRefusesOtherAlgorithms(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ParsePublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if !errors.Is(err, ErrBadFormat) || pk != nil {
		t.Fatalf("ParsePublicKeyPEM(P-256) = %v, %v; want nil, ErrBadFormat", pk, err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(ec)
	if priv, err := ParsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})); err == nil || priv != nil {
		t.Fatalf("ParsePrivateKeyPEM(P-256) = %v, %v; want an error", priv, err)
	}
}

// OpenOrCreate documents that it survives a creation race. Many callers meeting an absent
// ring at once must all get a usable keystore on the same file, none an ErrExist.
func TestOpenOrCreateRace(t *testing.T) {
	const callers = 32
	for round := 0; round < 25; round++ {
		path := filepath.Join(t.TempDir(), "r.ks")
		start := make(chan struct{})
		errs := make(chan error, callers)
		var wg sync.WaitGroup
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := OpenOrCreate(path)
				errs <- err
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("round %d: OpenOrCreate lost a creation race: %v", round, err)
			}
		}
	}
}

// The secret size contract: AddSecret mints exactly 32 bytes; ImportSecret takes 1 byte
// up to 64 KiB inclusive (literals: the numbers are the documented limits).
func TestSecretSizeContract(t *testing.T) {
	k, _ := newRing(t)
	got, err := k.AddSecret("minted", pass)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 {
		t.Fatalf("AddSecret returned %d bytes, want 32", len(got))
	}
	back, err := k.Secret("minted", pass)
	if err != nil || !bytes.Equal(back, got) {
		t.Fatalf("stored secret differs from the returned one: %v", err)
	}
	for n, ok := range map[int]bool{0: false, 1: true, 65535: true, 65536: true, 65537: false} {
		err := k.ImportSecret("s"+string(rune('a'+n%26))+string(rune('a'+n/26%26))+string(rune('a'+n/676%26)), bytes.Repeat([]byte{9}, n), pass)
		if ok && err != nil {
			t.Errorf("ImportSecret of %d bytes: %v", n, err)
		}
		if !ok && err == nil {
			t.Errorf("ImportSecret of %d bytes succeeded", n)
		}
	}
}

// ImportSecret must not consume or modify the caller's buffer.
func TestImportSecretLeavesTheCallersBufferAlone(t *testing.T) {
	k, _ := newRing(t)
	secret := []byte("do not zero this")
	want := append([]byte(nil), secret...)
	if err := k.ImportSecret("s", secret, pass); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, want) {
		t.Fatalf("caller's secret changed to %q", secret)
	}
	got, err := k.Secret("s", pass)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("stored %q, %v", got, err)
	}
}
