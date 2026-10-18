package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netstar-labs/keystore/pkg/keystore"
)

func TestSecretVerbsRoundTrip(t *testing.T) {
	r := ring(t)
	cli(t, "keygen", "-keystore", r, "-id", "sign")
	val := []byte("an api token \x00 with binary")
	b64 := base64.StdEncoding.EncodeToString(val)

	// stdin, with surrounding whitespace
	if _, _, err := cliIn(t, "  "+b64+"\n", "import-secret", "-keystore", r, "-id", "api"); err != nil {
		t.Fatal(err)
	}
	out, _, err := cli(t, "export-secret", "-keystore", r, "-id", "api")
	if err != nil || out != b64+"\n" {
		t.Fatalf("export-secret = %q, %v", out, err)
	}
	// -in FILE
	f := filepath.Join(t.TempDir(), "s.b64")
	os.WriteFile(f, []byte(b64), 0o600)
	if _, _, err := cli(t, "import-secret", "-keystore", r, "-id", "api2", "-in", f); err != nil {
		t.Fatal(err)
	}
	// add-secret prints nothing on stdout
	out, _, err = cli(t, "add-secret", "-keystore", r, "-id", "minted")
	if err != nil || out != "" {
		t.Fatalf("add-secret stdout %q, %v", out, err)
	}
	out, _, _ = cli(t, "export-secret", "-keystore", r, "-id", "minted")
	if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out)); err != nil || len(raw) != keystore.SecretSize {
		t.Fatalf("minted secret: %d bytes, %v", len(raw), err)
	}
	list, _, _ := cli(t, "list", "-keystore", r)
	if !strings.Contains(list, "api") || !strings.Contains(list, "secret") || strings.Contains(list, b64) {
		t.Fatalf("list = %q", list)
	}
}

func TestImportSecretRejects(t *testing.T) {
	r := ring(t)
	cli(t, "keygen", "-keystore", r, "-id", "sign")
	if _, _, err := cliIn(t, "not base64!!", "import-secret", "-keystore", r, "-id", "x"); err == nil {
		t.Fatal("invalid base64 accepted")
	}
	if _, _, err := cliIn(t, "", "import-secret", "-keystore", r, "-id", "x"); err == nil {
		t.Fatal("empty secret accepted")
	}
	huge := strings.Repeat("A", base64.StdEncoding.EncodedLen(keystore.MaxSecretSize)+8)
	if _, _, err := cliIn(t, huge, "import-secret", "-keystore", r, "-id", "x"); err == nil {
		t.Fatal("oversize input accepted")
	}
}

func TestImportSecretPromptsOnTerminal(t *testing.T) {
	r := ring(t)
	cli(t, "keygen", "-keystore", r, "-id", "sign")
	oldTerm, oldPrompt := isTerminal, promptSecret
	defer func() { isTerminal, promptSecret = oldTerm, oldPrompt }()
	isTerminal = func(*os.File) bool { return true }
	prompted := false
	promptSecret = func(string) ([]byte, error) {
		prompted = true
		return []byte(base64.StdEncoding.EncodeToString([]byte("typed"))), nil
	}
	fake, _ := os.CreateTemp(t.TempDir(), "tty")
	defer fake.Close()
	var out bytes.Buffer
	err := run([]string{"import-secret", "-keystore", r, "-id", "t"},
		&stdio{in: strings.NewReader("ignored"), out: &out, err: &out, inFile: fake})
	if err != nil || !prompted {
		t.Fatalf("import-secret on a terminal: %v, prompted=%v", err, prompted)
	}
}

func TestExportSecretGuards(t *testing.T) {
	r := ring(t)
	cli(t, "keygen", "-keystore", r, "-id", "sign")
	cli(t, "add-secret", "-keystore", r, "-id", "tok")
	old := isTerminal
	isTerminal = func(*os.File) bool { return true }
	defer func() { isTerminal = old }()
	fake, _ := os.CreateTemp(t.TempDir(), "tty")
	defer fake.Close()
	var out bytes.Buffer
	err := run([]string{"export-secret", "-keystore", r, "-id", "tok"}, &stdio{out: &out, err: &out, outFile: fake})
	if err == nil || out.Len() != 0 {
		t.Fatalf("export-secret to a terminal: %v, %d bytes", err, out.Len())
	}
	isTerminal = old
	ex := filepath.Join(t.TempDir(), "s")
	os.WriteFile(ex, []byte("old"), 0o644)
	if _, _, err := cli(t, "export-secret", "-keystore", r, "-id", "tok", "-o", ex); err == nil {
		t.Fatal("export-secret overwrote an existing file without -force")
	}
	if _, _, err := cli(t, "export-secret", "-keystore", r, "-id", "tok", "-o", ex, "-force"); err != nil {
		t.Fatal(err)
	}
	assertMode(t, ex, 0o600)
}

func TestPasswdVerb(t *testing.T) {
	r := ring(t)
	cli(t, "keygen", "-keystore", r, "-id", "sign")
	cli(t, "add-secret", "-keystore", r, "-id", "tok")
	before, _, _ := cli(t, "export-secret", "-keystore", r, "-id", "tok")

	t.Setenv("KEYSTORE_NEW_PASSPHRASE", testPass)
	if _, _, err := cli(t, "passwd", "-keystore", r); err == nil {
		t.Fatal("passwd to the same passphrase succeeded")
	}
	t.Setenv("KEYSTORE_NEW_PASSPHRASE", "short")
	if _, _, err := cli(t, "passwd", "-keystore", r); err == nil {
		t.Fatal("short new passphrase accepted")
	}
	const next = "the next ring passphrase"
	t.Setenv("KEYSTORE_NEW_PASSPHRASE", next)
	if _, _, err := cli(t, "passwd", "-keystore", r); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYSTORE_NEW_PASSPHRASE", "")
	if _, _, err := cli(t, "export-secret", "-keystore", r, "-id", "tok"); !errors.Is(err, keystore.ErrBadPass) {
		t.Fatalf("old passphrase after passwd: %v", err)
	}
	t.Setenv("KEYSTORE_PASSPHRASE", next)
	after, _, err := cli(t, "export-secret", "-keystore", r, "-id", "tok")
	if err != nil || after != before {
		t.Fatalf("secret changed across passwd: %v", err)
	}
	// A wrong current passphrase changes nothing.
	t.Setenv("KEYSTORE_PASSPHRASE", "definitely not it")
	t.Setenv("KEYSTORE_NEW_PASSPHRASE", "yet another passphrase")
	raw, _ := os.ReadFile(r)
	if _, _, err := cli(t, "passwd", "-keystore", r); !errors.Is(err, keystore.ErrBadPass) {
		t.Fatalf("passwd with wrong current passphrase: %v", err)
	}
	if now, _ := os.ReadFile(r); !bytes.Equal(raw, now) {
		t.Fatal("failed passwd modified the ring")
	}
}
