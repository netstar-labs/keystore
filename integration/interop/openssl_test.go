//go:build integration

// Package interop checks keystore against a real OpenSSL 3.x: the Ed25519 signatures,
// PEM encodings and fingerprints it produces must be accepted by OpenSSL, and what OpenSSL
// produces must be accepted by keystore. It runs wherever a capable `openssl` is on PATH:
// on the host only if that is OpenSSL 3 (macOS ships LibreSSL, which skips), and inside
// the Linux containers, where the runner installs OpenSSL 3.5.
package interop

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netstar-labs/keystore/integration/internal/livetest"
	"github.com/netstar-labs/keystore/internal/kdf"
)

type env struct {
	*livetest.Env
	ring string
	pf   string
}

// openssl runs the system openssl; stdin may be nil.
func openssl(t *testing.T, stdin []byte, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("openssl", args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(e.String()))
	}
	return o.String(), err
}

// setup skips unless this machine has an OpenSSL 3 that can do Ed25519 raw signing, then
// builds a ring with one key. The capability probe is the pre-check: a missing or old
// openssl is the environment's problem, never keystore's.
func setup(t *testing.T) *env {
	t.Helper()
	livetest.RequireLive(t)
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not on PATH")
	}
	ver, err := openssl(t, nil, "version")
	if err != nil || !strings.HasPrefix(ver, "OpenSSL 3") {
		t.Skipf("need OpenSSL 3.x, have %q (LibreSSL and 1.x lack Ed25519 raw signing)", strings.TrimSpace(ver))
	}
	t.Logf("openssl: %s", strings.TrimSpace(ver))
	if _, err := openssl(t, nil, "genpkey", "-algorithm", "ed25519"); err != nil {
		t.Skipf("this openssl cannot generate Ed25519 keys: %v", err)
	}
	le := livetest.NewEnv(t)
	return &env{Env: le, ring: filepath.Join(le.Dir, "r.ks"), pf: le.Passfile()}
}

// keystore signs, OpenSSL verifies; a tampered message is rejected by OpenSSL.
func TestKeystoreSignsOpenSSLVerifies(t *testing.T) {
	e := setup(t)
	pub := e.Write("k.pub", []byte(e.OK(e.KS(nil, "keygen", "-keystore", e.ring, "-passfile", e.pf, "-id", "k"), "keygen").Stdout))
	msg := e.Write("msg", []byte("hello from keystore\x00\xff binary too"))
	sig := filepath.Join(e.Dir, "msg.sig")
	e.OK(e.KS(nil, "sign", "-keystore", e.ring, "-passfile", e.pf, "-in", msg, "-raw", "-o", sig), "sign")
	if out, err := openssl(t, nil, "pkeyutl", "-verify", "-pubin", "-inkey", pub, "-rawin", "-in", msg, "-sigfile", sig); err != nil || !strings.Contains(out, "Signature Verified Successfully") {
		t.Fatalf("openssl rejected a keystore signature: %q %v", out, err)
	}
	bad := e.Write("bad", []byte("hello from keystore\x00\xff binary tooX"))
	if out, err := openssl(t, nil, "pkeyutl", "-verify", "-pubin", "-inkey", pub, "-rawin", "-in", bad, "-sigfile", sig); err == nil {
		t.Fatalf("known-bad: openssl accepted a signature over a different message: %q", out)
	}
	// the base64 form (the default output) decodes to the same 64 bytes
	b64 := e.OK(e.KS(nil, "sign", "-keystore", e.ring, "-passfile", e.pf, "-in", msg), "sign base64").Stdout
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != 64 {
		t.Fatalf("default signature output is not base64 of 64 bytes: %v %d", err, len(raw))
	}
	if out, err := openssl(t, nil, "pkeyutl", "-verify", "-pubin", "-inkey", pub, "-rawin", "-in", msg, "-sigfile", e.Write("b64.raw", raw)); err != nil {
		t.Fatalf("openssl rejected the base64-decoded signature: %q %v", out, err)
	}
}

// OpenSSL signs, keystore verifies (exit 0); tampered -> exit 3, not a generic failure.
func TestOpenSSLSignsKeystoreVerifies(t *testing.T) {
	e := setup(t)
	priv := filepath.Join(e.Dir, "o.priv")
	if _, err := openssl(t, nil, "genpkey", "-algorithm", "ed25519", "-out", priv); err != nil {
		t.Fatal(err)
	}
	pubPEM, err := openssl(t, nil, "pkey", "-in", priv, "-pubout")
	if err != nil {
		t.Fatal(err)
	}
	pub := e.Write("o.pub", []byte(pubPEM))
	msg := e.Write("m", []byte("signed by openssl"))
	sig := filepath.Join(e.Dir, "m.sig")
	if _, err := openssl(t, nil, "pkeyutl", "-sign", "-inkey", priv, "-rawin", "-in", msg, "-out", sig); err != nil {
		t.Fatal(err)
	}
	e.OK(e.KS(nil, "verify", "-pub", pub, "-sig", sig, "-in", msg), "verify an openssl signature")
	bad := e.Write("m2", []byte("signed by opensslX"))
	if r := e.KS(nil, "verify", "-pub", pub, "-sig", sig, "-in", bad); r.Exit != 3 {
		t.Fatalf("known-bad: tampered message exit = %d, want 3\n%s", r.Exit, r.Stderr)
	}

	// An OpenSSL-generated key imported into a ring signs signatures OpenSSL accepts, and the
	// ring reports the same fingerprint OpenSSL derives.
	e.OK(e.KS(nil, "init", "-keystore", e.ring), "init")
	e.OK(e.KS(nil, "import", "-keystore", e.ring, "-passfile", e.pf, "-id", "imp", "-key", priv), "import openssl key")
	sig2 := filepath.Join(e.Dir, "m.sig2")
	e.OK(e.KS(nil, "sign", "-keystore", e.ring, "-passfile", e.pf, "-id", "imp", "-in", msg, "-raw", "-o", sig2), "sign with imported key")
	if out, err := openssl(t, nil, "pkeyutl", "-verify", "-pubin", "-inkey", pub, "-rawin", "-in", msg, "-sigfile", sig2); err != nil {
		t.Fatalf("openssl rejected a signature from the imported key: %q %v", out, err)
	}
	// Ed25519 is deterministic: both implementations must produce byte-identical signatures.
	a, _ := os.ReadFile(sig)
	b, _ := os.ReadFile(sig2)
	if !bytes.Equal(a, b) {
		t.Fatalf("Ed25519 is deterministic but signatures differ:\nopenssl  %x\nkeystore %x", a, b)
	}
}

// export-pub / export-priv PEMs parse in `openssl pkey`, describe the same key, and the
// ring's fingerprint equals the SHA-256 of the SPKI DER that OpenSSL produces.
func TestExportsAndFingerprintMatchOpenSSL(t *testing.T) {
	e := setup(t)
	e.OK(e.KS(nil, "keygen", "-keystore", e.ring, "-passfile", e.pf, "-id", "k"), "keygen")
	pubPEM := e.OK(e.KS(nil, "export-pub", "-keystore", e.ring, "-id", "k"), "export-pub").Stdout
	privFile := filepath.Join(e.Dir, "k.priv")
	e.OK(e.KS(nil, "export-priv", "-keystore", e.ring, "-passfile", e.pf, "-id", "k", "-o", privFile), "export-priv")

	if _, err := openssl(t, []byte(pubPEM), "pkey", "-pubin", "-noout"); err != nil {
		t.Fatalf("openssl cannot parse export-pub: %v", err)
	}
	if text, err := openssl(t, nil, "pkey", "-in", privFile, "-noout", "-text"); err != nil || !strings.Contains(text, "ED25519") {
		t.Fatalf("openssl cannot parse export-priv as Ed25519: %q %v", text, err)
	}
	derived, err := openssl(t, nil, "pkey", "-in", privFile, "-pubout")
	if err != nil || derived != pubPEM {
		t.Fatalf("public key derived by openssl from export-priv differs from export-pub:\n%q\n%q (%v)", derived, pubPEM, err)
	}
	der, err := openssl(t, []byte(pubPEM), "pkey", "-pubin", "-outform", "DER")
	if err != nil {
		t.Fatal(err)
	}
	want := "SHA256:" + base64.RawStdEncoding.EncodeToString(func() []byte { s := sha256.Sum256([]byte(der)); return s[:] }())
	// Same figure via openssl itself, so the check does not rest on Go's hash alone.
	dg, err := openssl(t, []byte(der), "dgst", "-sha256", "-binary")
	if err != nil {
		t.Fatal(err)
	}
	if viaOpenSSL := "SHA256:" + base64.RawStdEncoding.EncodeToString([]byte(dg)); viaOpenSSL != want {
		t.Fatalf("hash disagreement inside the test: %s vs %s", viaOpenSSL, want)
	}
	list := e.OK(e.KS(nil, "list", "-keystore", e.ring), "list").Stdout
	if !strings.Contains(list, want) {
		t.Fatalf("fingerprint %s (openssl-derived) not in `keystore list`:\n%s", want, list)
	}
}

// The ring's KDF is Argon2id; the key kdf.Derive makes must equal OpenSSL's Argon2id for the
// same passphrase, salt and cost (a second implementation, written by someone else).
func TestArgon2idMatchesOpenSSL(t *testing.T) {
	setup(t)
	salt := []byte("0123456789abcdef")
	p := kdf.Params{Algo: kdf.Algo, Mem: 8 * 1024, Time: 2, Par: 1, Salt: salt}
	got, err := p.Derive([]byte("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := openssl(t, nil, "kdf", "-keylen", "32", "-binary",
		"-kdfopt", "pass:correct horse", "-kdfopt", "hexsalt:"+hex.EncodeToString(salt),
		"-kdfopt", "iter:2", "-kdfopt", "memcost:8192", "-kdfopt", "lanes:1", "-kdfopt", "threads:1", "ARGON2ID")
	if err != nil {
		t.Skipf("this openssl has no usable `kdf ARGON2ID`: %v", err)
	}
	if !bytes.Equal([]byte(out), got) {
		t.Fatalf("Argon2id mismatch:\nkeystore %x\nopenssl  %x", got, []byte(out))
	}
}
