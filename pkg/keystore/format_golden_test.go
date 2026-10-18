package keystore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"
)

// Golden outputs for the RFC 8032 test-1 key (seed 9d61b19d...). The PEM text was built
// from the RFC 8410 layout by a Python script (fixed DER prefix + key, base64, 64-column
// lines) and then checked against OpenSSL 3.5.9: `openssl pkey -pubout` on the private
// PEM reproduced the public PEM byte for byte, `openssl pkey` re-emitted the private PEM
// byte for byte, and `openssl dgst -sha256` over the SPKI DER gave the fingerprint. They
// are not "whatever Go emits". Other tools read these files: ssh-keygen/openssl/age-style
// verifiers parse the PEM, and the fingerprint is what operators pin with -expect-fp.

const (
	rfcSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	rfcPrivPEM = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE KEY-----\n"
	rfcPubPEM  = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n"
	rfcFP      = "SHA256:BuP9j9opu2CrWVV95h7bCuzbIxE0vjDnW0Vfjht5L6k"
)

const outputBreak = "OUTPUT ENCODING CHANGED (%s). Other tools parse this output (OpenSSL, ssh-style verifiers, scripts that pin " +
	"fingerprints with -expect-fp); a changed byte is read as a different key or a mismatch, not as an error. " +
	"Do not re-record this golden to make the test pass."

func rfcKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(rfcSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestPEMGolden(t *testing.T) {
	priv := rfcKey(t)
	gotPriv, err := MarshalPrivateKeyPEM(priv)
	if err != nil || string(gotPriv) != rfcPrivPEM {
		t.Errorf(outputBreak+"\n got  %q, %v\n want %q", "PKCS#8 private PEM", gotPriv, err, rfcPrivPEM)
	}
	gotPub, err := MarshalPublicKeyPEM(priv.Public().(ed25519.PublicKey))
	if err != nil || string(gotPub) != rfcPubPEM {
		t.Errorf(outputBreak+"\n got  %q, %v\n want %q", "SPKI public PEM", gotPub, err, rfcPubPEM)
	}
	// The read side accepts the independently built text.
	if k, err := ParsePrivateKeyPEM([]byte(rfcPrivPEM)); err != nil || !bytes.Equal(k, priv) {
		t.Errorf("ParsePrivateKeyPEM(golden) = %x, %v", k, err)
	}
	if k, err := ParsePublicKeyPEM([]byte(rfcPubPEM)); err != nil || !k.Equal(priv.Public()) {
		t.Errorf("ParsePublicKeyPEM(golden) = %x, %v", k, err)
	}
}

func TestFingerprintGolden(t *testing.T) {
	if got := Fingerprint(rfcKey(t).Public().(ed25519.PublicKey)); got != rfcFP {
		t.Errorf(outputBreak+"\n got  %s\n want %s", "fingerprint", got, rfcFP)
	}
}

// The plaintext of an ed25519 entry is the PKCS#8 DER of the key. The expected bytes are
// the RFC 8410 layout (a fixed 16-byte prefix, then the seed), built by hand, not by
// x509. Checked on both sides: what an old build encrypted into golden.ks decrypts to
// exactly this, and what this build would encrypt for the same key is exactly this.
// (A Go toolchain that emitted a v2 key with the public half would change new entries'
// plaintext silently; format.md says readers ignore that, but nothing else noticed.)
func TestEntryPlaintextIsPKCS8V1(t *testing.T) {
	want := "302e020100300506032b657004220420" + hex.EncodeToString(goldenSeed)
	k, err := Open(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := unlock(k.f.Find(goldenID), []byte(goldenPass))
	if err != nil || hex.EncodeToString(pt) != want {
		t.Errorf("golden.ks ed25519 plaintext = %x, %v; want %s", pt, err, want)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(goldenSeed))
	if err != nil || hex.EncodeToString(der) != want {
		t.Errorf("PLAINTEXT ENCODING CHANGED: new entries would encrypt %x, %v; want %s. Old builds parse it with x509.ParsePKCS8PrivateKey; do not re-record.", der, err, want)
	}
}

// Edge rings under testdata/ still open with this build: an empty ring, a minimal one
// (`{"magic":"keystore/v1"}`) and a ring holding only a secret (taken from golden.ks, so
// its ciphertext is the real production-cost one).
func TestEdgeRingFixturesOpen(t *testing.T) {
	for _, name := range []string{"ring-empty.ks", "ring-minimal.ks"} {
		k, err := Open("../../testdata/" + name)
		if err != nil || len(k.List()) != 0 || k.CurrentID() != "" {
			t.Errorf("%s: %v, current %q", name, err, k.CurrentID())
			continue
		}
		if _, err := k.Public(""); !errors.Is(err, ErrNoKey) {
			t.Errorf("%s: Public(\"\") = %v, want ErrNoKey", name, err)
		}
	}
	k, err := Open("../../testdata/ring-secret-only.ks")
	if err != nil {
		t.Fatal(err)
	}
	if k.CurrentID() != "" || len(k.List()) != 1 {
		t.Fatalf("secret-only ring: current %q, %d entries", k.CurrentID(), len(k.List()))
	}
	if sec, err := k.Secret(goldenSecretID, []byte(goldenPass)); err != nil || !bytes.Equal(sec, goldenSecret) {
		t.Errorf("secret-only ring: Secret = %x, %v", sec, err)
	}
	if _, err := k.Signer("", []byte(goldenPass)); !errors.Is(err, ErrNoKey) {
		t.Errorf("secret-only ring: Signer(\"\") = %v, want ErrNoKey", err)
	}
}
