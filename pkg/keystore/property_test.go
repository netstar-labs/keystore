package keystore

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	"github.com/netstar-labs/keystore/internal/ringfile"
)

// scope.md property 1: a copy of the ring file alone reveals no private material. Try to
// find the seed, the secret bytes or the passphrase in the file, in any of the encodings a
// careless writer might leave them in.
func TestRingFileHoldsNoPlaintext(t *testing.T) {
	k, path := newRing(t)
	if _, err := k.Add("sign", pass); err != nil {
		t.Fatal(err)
	}
	minted, err := k.AddSecret("minted", pass)
	if err != nil {
		t.Fatal(err)
	}
	imported := []byte("an imported secret with a recognisable tail 0123456789")
	if err := k.ImportSecret("imported", imported, pass); err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(nil)
	if err := k.Import("imported-key", priv, pass); err != nil {
		t.Fatal(err)
	}
	signer, err := k.ExportPrivate("sign", pass)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	needles := map[string][]byte{
		"signing seed":      signer.Seed(),
		"imported seed":     priv.Seed(),
		"minted secret":     minted,
		"imported secret":   imported,
		"passphrase":        pass,
		"private half only": signer[:32],
	}
	for name, n := range needles {
		forms := [][]byte{n, []byte(base64.StdEncoding.EncodeToString(n)), []byte(base64.RawStdEncoding.EncodeToString(n)), []byte(hex.EncodeToString(n))}
		for _, f := range forms {
			if bytes.Contains(raw, f) {
				t.Errorf("the ring file contains the %s (as %q...)", name, f[:min(len(f), 12)])
			}
		}
	}
}

// Every entry has its own salt and nonce, and re-encrypting under a new passphrase draws
// fresh ones for all of them (a reused salt or nonce under a new key is harmless, but
// under the same key a reused nonce is catastrophic: nothing may carry one over).
func TestSaltsAndNoncesAreUniquePerEntryAndFreshAfterPasswd(t *testing.T) {
	k, path := newRing(t)
	k.Add("a", pass)
	k.Add("b", pass)
	k.AddSecret("c", pass)
	k.AddSecret("d", pass)
	read := func() []ringfile.Entry {
		f, err := ringfile.Read(path)
		if err != nil {
			t.Fatal(err)
		}
		return f.Entries
	}
	distinct := func(es []ringfile.Entry) {
		t.Helper()
		salts, nonces := map[string]bool{}, map[string]bool{}
		for _, e := range es {
			if salts[string(e.KDF.Salt)] || nonces[string(e.Nonce)] {
				t.Fatalf("entry %s shares a salt or nonce with another entry", e.ID)
			}
			salts[string(e.KDF.Salt)], nonces[string(e.Nonce)] = true, true
		}
	}
	before := read()
	distinct(before)
	if err := k.ChangePassphrase(pass, []byte("a brand new passphrase")); err != nil {
		t.Fatal(err)
	}
	after := read()
	distinct(after)
	for i := range before {
		if bytes.Equal(before[i].KDF.Salt, after[i].KDF.Salt) || bytes.Equal(before[i].Nonce, after[i].Nonce) {
			t.Errorf("entry %s kept its salt or nonce across passwd", before[i].ID)
		}
		if !before[i].Created.Equal(after[i].Created) || before[i].ID != after[i].ID || !bytes.Equal(before[i].Pub, after[i].Pub) {
			t.Errorf("entry %s changed identity across passwd", before[i].ID)
		}
	}
}
