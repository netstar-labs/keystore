package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Golden CLI outputs for the RFC 8032 test-1 key. Ed25519 is deterministic, so the
// signature over "keystore golden" is a constant; it was produced by OpenSSL 3.5.9
// (`openssl pkeyutl -sign -rawin`), not by this program. The PEM and fingerprint were
// cross-checked the same way (see pkg/keystore/format_golden_test.go).
const (
	goldenPrivPEM = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE KEY-----\n"
	goldenPubPEM  = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n"
	goldenFP      = "SHA256:BuP9j9opu2CrWVV95h7bCuzbIxE0vjDnW0Vfjht5L6k"
	goldenSigB64  = "hxkSe7Si3tb/jjRV+d7U2zZJwRoZbHmvRLt+gVnvYRGjIFSSoQ8tXdH7o4y1xLdS2MyjEArDu1GHyW7+KdPpBw=="
)

const cliBreak = "CLI OUTPUT ENCODING CHANGED (%s). Scripts and verifiers consume these bytes verbatim (base64 plus one newline, " +
	"or 64 raw bytes, PEM text, the SHA256: fingerprint); a change is a silent mismatch for them, not an error. " +
	"Do not re-record this golden to make the test pass."

func TestCLIOutputGoldens(t *testing.T) {
	r := ring(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "k.pem")
	msg := filepath.Join(dir, "msg")
	os.WriteFile(key, []byte(goldenPrivPEM), 0o600)
	os.WriteFile(msg, []byte("keystore golden"), 0o644)
	if _, _, err := cli(t, "init", "-keystore", r); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cli(t, "import", "-keystore", r, "-id", "rfc", "-key", key); err != nil {
		t.Fatal(err)
	}

	out, errOut, err := cli(t, "sign", "-keystore", r, "-in", msg)
	if err != nil || out != goldenSigB64+"\n" {
		t.Errorf(cliBreak+"\n got %q, %v", "sign base64", out, err)
	}
	if want := "signing with " + goldenFP + "\n"; errOut != want {
		t.Errorf(cliBreak+"\n got %q want %q", "sign stderr fingerprint line", errOut, want)
	}
	raw := filepath.Join(dir, "sig.bin")
	if _, _, err := cli(t, "sign", "-keystore", r, "-in", msg, "-raw", "-o", raw); err != nil {
		t.Fatal(err)
	}
	wantRaw, _ := base64.StdEncoding.DecodeString(goldenSigB64)
	if got, _ := os.ReadFile(raw); string(got) != string(wantRaw) || len(got) != 64 {
		t.Errorf(cliBreak+" got %x", "sign -raw", got)
	}

	if pub, _, err := cli(t, "export-pub", "-keystore", r); err != nil || pub != goldenPubPEM {
		t.Errorf(cliBreak+"\n got %q, %v", "export-pub", pub, err)
	}
	priv := filepath.Join(dir, "out.pem")
	if _, _, err := cli(t, "export-priv", "-keystore", r, "-o", priv); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(priv); string(got) != goldenPrivPEM {
		t.Errorf(cliBreak+"\n got %q", "export-priv", got)
	}
	// list: the fingerprint is the last column (the created column is the clock's).
	list, _, err := cli(t, "list", "-keystore", r)
	if f := strings.Fields(list); err != nil || len(f) == 0 || f[len(f)-1] != goldenFP {
		t.Errorf(cliBreak+"\n got %q, %v", "list fingerprint column", list, err)
	}
}
