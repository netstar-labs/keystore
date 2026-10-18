package main

import (
	"errors"
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
func TestVerifyInputFilesAreCapped(t *testing.T) {
	_, pub, _ := signFixture(t)
	big := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(big, make([]byte, maxInputFile+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cliIn(t, "m", "verify", "-pub", big, "-sig", big); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("oversize -pub: %v", err)
	}
	if _, _, err := cliIn(t, "m", "verify", "-pub", pub, "-sig", big); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("oversize -sig: %v", err)
	}
}
