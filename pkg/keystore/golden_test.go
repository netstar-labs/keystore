package keystore

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/netstar-labs/keystore/internal/kdf"
)

var update = flag.Bool("update", false, "rewrite testdata/golden.ks")

const (
	goldenPath = "../../testdata/golden.ks"
	goldenPass = "golden ring passphrase"
	goldenID   = "golden-ed25519"
)

// goldenSeed is the Ed25519 seed of the golden key: bytes 0x00..0x1f.
var goldenSeed = func() []byte {
	b := make([]byte, ed25519.SeedSize)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}()

// Values derived from goldenSeed; recorded once and checked against the stdlib on every
// run, so the fixture, the seed and these constants cannot drift apart silently.
const (
	goldenPubHex = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
	goldenSigHex = "e59248bf76ba03838c281e5054f1f42c2275b10ca785ec76cfca306afb6ec57340f6f1f0b60cf346de668bcb83c68dcac8b8ed758c7e279c96536cc0ee75a30c"
)

// TestGolden pins ring format v1: a ring written at the production KDF cost must open,
// unlock with the documented passphrase, and yield the documented key.
func TestGolden(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(goldenSeed)
	if *update {
		prod := kdf.Default
		kdf.Default = kdf.Cost{Mem: 64 * 1024, Time: 3, Par: 1}
		defer func() { kdf.Default = prod }()
		tmp := filepath.Join(t.TempDir(), "golden.ks")
		k, err := Create(tmp)
		if err != nil {
			t.Fatal(err)
		}
		if err := k.Import(goldenID, priv, []byte(goldenPass)); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(tmp)
		if err := os.WriteFile(goldenPath, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if hex.EncodeToString(priv.Public().(ed25519.PublicKey)) != goldenPubHex {
		t.Fatalf("seed → public key changed: %x", priv.Public())
	}
	k, err := Open(goldenPath)
	if err != nil {
		t.Fatalf("golden ring does not open: %v", err)
	}
	if k.CurrentID() != goldenID {
		t.Fatalf("current = %q", k.CurrentID())
	}
	pub, err := k.Public(goldenID)
	if err != nil || hex.EncodeToString(pub) != goldenPubHex {
		t.Fatalf("golden public key = %x, %v", pub, err)
	}
	s, err := k.Signer(goldenID, []byte(goldenPass))
	if err != nil {
		t.Fatalf("golden ring does not unlock: %v", err)
	}
	sig, _ := s.Sign(nil, []byte("keystore golden"), &ed25519.Options{})
	if hex.EncodeToString(sig) != goldenSigHex {
		t.Fatalf("golden signature = %x", sig)
	}
	if !bytes.Equal(sig, ed25519.Sign(priv, []byte("keystore golden"))) {
		t.Fatal("unlocked key differs from the seed key")
	}
}
