package keystore

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"
)

func TestSecretsRoundTrip(t *testing.T) {
	k, path := newRing(t)
	minted, err := k.AddSecret("tok", pass)
	if err != nil || len(minted) != SecretSize {
		t.Fatalf("AddSecret = %d bytes, %v", len(minted), err)
	}
	if err := k.ImportSecret("api", []byte("imported value"), pass); err != nil {
		t.Fatal(err)
	}
	k2, _ := Open(path)
	got, err := k2.Secret("tok", pass)
	if err != nil || !bytes.Equal(got, minted) {
		t.Fatalf("Secret(tok) = %x, %v", got, err)
	}
	got, _ = k2.Secret("api", pass)
	if string(got) != "imported value" {
		t.Fatalf("Secret(api) = %q", got)
	}
	if k2.CurrentID() != "" {
		t.Fatalf("a secret became current: %q", k2.CurrentID())
	}
	if _, err := k2.Secret("tok", []byte("wrong passphrase")); !errors.Is(err, ErrBadPass) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	for _, e := range k2.List() {
		if e.Public != nil || e.Fingerprint != "" {
			t.Fatalf("secret listed with key material: %+v", e)
		}
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("imported value")) {
		t.Fatal("secret stored in cleartext")
	}
}

func TestSecretKindChecks(t *testing.T) {
	k, _ := newRing(t)
	k.Add("sign", pass)
	k.AddSecret("tok", pass)
	if _, err := k.Secret("sign", pass); !errors.Is(err, ErrNotSecret) {
		t.Fatalf("Secret on a signing key: %v", err)
	}
	if _, err := k.Signer("tok", pass); !errors.Is(err, ErrNotSigningKey) {
		t.Fatalf("Signer on a secret: %v", err)
	}
	if err := k.Use("tok"); !errors.Is(err, ErrNotSigningKey) {
		t.Fatalf("Use on a secret: %v", err)
	}
	if err := k.Remove("tok", false); err != nil {
		t.Fatalf("removing a secret needs no force: %v", err)
	}
}

func TestSecretPassphraseInvariantAndBounds(t *testing.T) {
	k, path := newRing(t)
	k.Add("sign", pass)
	before, _ := os.ReadFile(path)
	if _, err := k.AddSecret("tok", []byte("another passphrase")); !errors.Is(err, ErrPassphraseMismatch) {
		t.Fatalf("AddSecret with other passphrase: %v", err)
	}
	if err := k.ImportSecret("e", nil, pass); err == nil {
		t.Fatal("empty secret accepted")
	}
	if err := k.ImportSecret("big", make([]byte, MaxSecretSize+1), pass); err == nil {
		t.Fatal("oversize secret accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("refused secret adds changed the ring")
	}
	// A ring holding only secrets still enforces one passphrase.
	k2, _ := newRing(t)
	k2.AddSecret("a", pass)
	if _, err := k2.Add("sign", []byte("another passphrase")); !errors.Is(err, ErrPassphraseMismatch) {
		t.Fatalf("signing key into a secrets-only ring with other passphrase: %v", err)
	}
}

func TestChangePassphrase(t *testing.T) {
	k, path := newRing(t)
	pub, _ := k.Add("sign", pass)
	sec, _ := k.AddSecret("tok", pass)
	before := k.List()
	newPass := []byte("the replacement passphrase")
	if err := k.ChangePassphrase(pass, newPass); err != nil {
		t.Fatal(err)
	}
	k2, _ := Open(path)
	if _, err := k2.Signer("sign", pass); !errors.Is(err, ErrBadPass) {
		t.Fatalf("old passphrase still unlocks: %v", err)
	}
	s, err := k2.Signer("sign", newPass)
	if err != nil || !s.Public().(ed25519.PublicKey).Equal(pub) {
		t.Fatalf("new passphrase: %v", err)
	}
	got, err := k2.Secret("tok", newPass)
	if err != nil || !bytes.Equal(got, sec) {
		t.Fatalf("secret after passwd: %v", err)
	}
	after := k2.List()
	for i := range before {
		if before[i].ID != after[i].ID || !before[i].Created.Equal(after[i].Created) || before[i].Current != after[i].Current {
			t.Fatalf("metadata changed: %+v → %+v", before[i], after[i])
		}
	}
	// Further adds now require the new passphrase.
	if _, err := k2.Add("x", pass); !errors.Is(err, ErrPassphraseMismatch) {
		t.Fatalf("add with old passphrase after passwd: %v", err)
	}
}

func TestChangePassphraseWrongOldWritesNothing(t *testing.T) {
	k, path := newRing(t)
	k.Add("sign", pass)
	k.AddSecret("tok", pass)
	before, _ := os.ReadFile(path)
	if err := k.ChangePassphrase([]byte("not it"), []byte("whatever new one")); !errors.Is(err, ErrBadPass) {
		t.Fatalf("wrong old passphrase: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed passwd modified the ring")
	}
}

// If any one entry fails to unlock, no entry is re-encrypted.
func TestChangePassphraseAllOrNothing(t *testing.T) {
	k, path := newRing(t)
	k.Add("sign", pass)
	k.AddSecret("tok", pass)
	raw, _ := os.ReadFile(path)
	// Corrupt the second entry's ciphertext only.
	corrupt := bytes.Replace(raw, []byte(`"ct": "`), []byte(`"ct": "AAAA`), 2)
	corrupt = bytes.Replace(corrupt, []byte(`"ct": "AAAA`), []byte(`"ct": "`), 1)
	os.WriteFile(path, corrupt, 0o600)
	k2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := k2.ChangePassphrase(pass, []byte("a new passphrase here")); !errors.Is(err, ErrBadPass) {
		t.Fatalf("passwd over a corrupt entry: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(corrupt, after) {
		t.Fatal("passwd partially rewrote the ring")
	}
	if _, err := k2.Signer("sign", pass); err != nil {
		t.Fatalf("intact entry no longer opens with the old passphrase: %v", err)
	}
}

func TestChangePassphraseEmptyRing(t *testing.T) {
	k, _ := newRing(t)
	if err := k.ChangePassphrase(pass, []byte("a new passphrase here")); err == nil {
		t.Fatal("passwd on an empty ring succeeded")
	}
}
