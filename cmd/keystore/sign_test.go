package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netstar-labs/keystore/pkg/agent"
	"github.com/netstar-labs/keystore/pkg/keystore"
)

func signFixture(t *testing.T) (r, pub, msg string) {
	t.Helper()
	r = ring(t)
	pemOut, _, err := cli(t, "keygen", "-keystore", r, "-id", "prod")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pub = filepath.Join(dir, "prod.pub")
	os.WriteFile(pub, []byte(pemOut), 0o644)
	msg = filepath.Join(dir, "msg")
	os.WriteFile(msg, []byte("release v1.2.3 sha256=abc"), 0o644)
	return r, pub, msg
}

func TestSignVerifyWithRing(t *testing.T) {
	r, pub, msg := signFixture(t)
	sigOut, _, err := cli(t, "sign", "-keystore", r, "-in", msg)
	if err != nil {
		t.Fatal(err)
	}
	sig := filepath.Join(t.TempDir(), "sig")
	os.WriteFile(sig, []byte(sigOut), 0o644)
	if _, _, err := cli(t, "verify", "-pub", pub, "-sig", sig, "-in", msg); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// stdin form
	if _, _, err := cliIn(t, "release v1.2.3 sha256=abc", "verify", "-pub", pub, "-sig", sig); err != nil {
		t.Fatalf("verify from stdin: %v", err)
	}
	// tampered message
	if _, _, err := cliIn(t, "release v1.2.4 sha256=abc", "verify", "-pub", pub, "-sig", sig); !errors.Is(err, errBadSig) {
		t.Fatalf("tampered message: %v", err)
	}
	// wrong key
	other := filepath.Join(t.TempDir(), "other.ks")
	otherPEM, _, _ := cli(t, "keygen", "-keystore", other, "-id", "x")
	op := filepath.Join(t.TempDir(), "other.pub")
	os.WriteFile(op, []byte(otherPEM), 0o644)
	if _, _, err := cli(t, "verify", "-pub", op, "-sig", sig, "-in", msg); !errors.Is(err, errBadSig) {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestSignRawAndFileOutput(t *testing.T) {
	r, pub, msg := signFixture(t)
	sig := filepath.Join(t.TempDir(), "sig.bin")
	if _, _, err := cli(t, "sign", "-keystore", r, "-in", msg, "-raw", "-o", sig); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(sig); st.Size() != 64 {
		t.Fatalf("raw signature is %d bytes", st.Size())
	}
	if _, _, err := cli(t, "verify", "-pub", pub, "-sig", sig, "-in", msg); err != nil {
		t.Fatalf("verify raw: %v", err)
	}
	if _, _, err := cli(t, "sign", "-keystore", r, "-in", msg, "-o", sig); err == nil {
		t.Fatal("sign overwrote an existing -o file without -force")
	}
}

func TestSignViaAgent(t *testing.T) {
	r, pub, msg := signFixture(t)
	k, _ := keystore.Open(r)
	priv, _ := k.ExportPrivate("", []byte(testPass))
	srv, _ := agent.NewServer(priv)
	dir, _ := os.MkdirTemp("/tmp", "kc")
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "a.sock")
	ln, err := agent.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	t.Setenv("KEYSTORE_PASSPHRASE", "") // the agent path must not need it (Prompt fails the test)
	sigOut, _, err := cli(t, "sign", "-agent", sock, "-in", msg)
	if err != nil {
		t.Fatalf("sign -agent: %v", err)
	}
	sig := filepath.Join(t.TempDir(), "sig")
	os.WriteFile(sig, []byte(sigOut), 0o644)
	if _, _, err := cli(t, "verify", "-pub", pub, "-sig", sig, "-in", msg); err != nil {
		t.Fatalf("agent signature does not verify: %v", err)
	}
	if _, errOut, _ := cli(t, "sign", "-agent", sock, "-in", msg); !strings.Contains(errOut, "signing with SHA256:") {
		t.Errorf("sign -agent does not name the agent's key: %q", errOut)
	}
	if _, _, err := cli(t, "sign", "-agent", sock, "-id", "prod", "-in", msg); !isUsage(err) {
		t.Fatalf("-agent with -id: %v", err)
	}
	srv.Close()
	if _, _, err := cli(t, "sign", "-agent", sock, "-in", msg); err == nil {
		t.Fatal("sign through a stopped agent succeeded")
	}
}

func TestSignVerifyLimits(t *testing.T) {
	r, pub, _ := signFixture(t)
	big := strings.Repeat("x", maxMessage+1)
	if _, _, err := cliIn(t, big, "sign", "-keystore", r); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("oversize sign: %v", err)
	}
	junk := filepath.Join(t.TempDir(), "junk")
	os.WriteFile(junk, []byte("not a signature"), 0o644)
	if _, _, err := cliIn(t, "m", "verify", "-pub", pub, "-sig", junk); err == nil || errors.Is(err, errBadSig) {
		t.Fatalf("malformed signature file: %v", err)
	}
}

// verify read its -pub and -sig files whole, unlike every other input (a planted 1 GiB
// file cost ~1-2 GB of memory). A PEM public key or a signature is a few hundred bytes.
// The boundary is a literal 64 KiB so the test does not move with the constant: a file of
// exactly that size (a valid key padded with newlines) verifies, one byte more is refused.
func TestVerifyInputFilesAreCapped(t *testing.T) {
	r, pub, msg := signFixture(t)
	dir := t.TempDir()
	pad := func(src string, size int) string {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, bytes.Repeat([]byte("\n"), size-len(b))...)
		p := filepath.Join(dir, fmt.Sprintf("padded-%d-%s", size, filepath.Base(src)))
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	sig := filepath.Join(dir, "m.sig")
	if _, _, err := cli(t, "sign", "-keystore", r, "-in", msg, "-o", sig); err != nil {
		t.Fatal(err)
	}
	const limit = 64 << 10
	if _, _, err := cli(t, "verify", "-pub", pad(pub, limit), "-sig", pad(sig, limit), "-in", msg); err != nil {
		t.Errorf("inputs of exactly 64 KiB were refused: %v", err)
	}
	for name, args := range map[string][]string{
		"-pub": {"-pub", pad(pub, limit+1), "-sig", sig},
		"-sig": {"-pub", pub, "-sig", pad(sig, limit+1)},
	} {
		_, _, err := cli(t, append([]string{"verify", "-in", msg}, args...)...)
		if err == nil || !strings.Contains(err.Error(), "too large") {
			t.Errorf("oversize %s: %v", name, err)
		}
	}
}

// The ring's `current` marker is unauthenticated, so a bare `sign` signs with whichever key
// the file names; the only visible trace used to be a later `list`. sign now says which key
// it used, and -expect-fp pins it (the non-format mitigation recorded in decision 39).
func TestSignReportsTheKeyAndHonoursExpectFP(t *testing.T) {
	r, pubFile, msg := signFixture(t) // key "prod" is current
	pemA, _ := os.ReadFile(pubFile)
	pubA, err := keystore.ParsePublicKeyPEM(pemA)
	if err != nil {
		t.Fatal(err)
	}
	fpA := keystore.Fingerprint(pubA)
	pemB, _, err := cli(t, "add", "-keystore", r, "-id", "other")
	if err != nil {
		t.Fatal(err)
	}
	pubB, _ := keystore.ParsePublicKeyPEM([]byte(pemB))
	fpB := keystore.Fingerprint(pubB)

	// The key used is named on stderr, with and without a pin.
	_, errOut, err := cli(t, "sign", "-keystore", r, "-in", msg)
	if err != nil || !strings.Contains(errOut, "signing with "+fpA) {
		t.Fatalf("sign: err %v, stderr %q, want it to name %s", err, errOut, fpA)
	}
	if _, errOut, err = cli(t, "sign", "-keystore", r, "-in", msg, "-expect-fp", fpA); err != nil || !strings.Contains(errOut, fpA) {
		t.Fatalf("sign -expect-fp (matching): %v, %q", err, errOut)
	}
	// `current` moves (an edit by anything that can write the ring looks exactly like this).
	if _, _, err := cli(t, "use", "-keystore", r, "-id", "other"); err != nil {
		t.Fatal(err)
	}
	out, _, err := cli(t, "sign", "-keystore", r, "-in", msg, "-expect-fp", fpA)
	if err == nil || out != "" {
		t.Fatalf("sign with a moved current and -expect-fp %s: out %q err %v, want a refusal and no signature", fpA, out, err)
	}
	if !strings.Contains(err.Error(), fpA) || !strings.Contains(err.Error(), fpB) {
		t.Errorf("error %q should name both the key it would have used (%s) and the expected one (%s)", err, fpB, fpA)
	}
	// -id is the other pin, and still works.
	if _, errOut, err = cli(t, "sign", "-keystore", r, "-in", msg, "-id", "prod"); err != nil || !strings.Contains(errOut, fpA) {
		t.Errorf("sign -id prod: %v, %q", err, errOut)
	}
}
