package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/netstar-labs/keystore/internal/kdf"
	"github.com/netstar-labs/keystore/internal/passphrase"
	"github.com/netstar-labs/keystore/pkg/keystore"
)

var update = flag.Bool("update", false, "rewrite docs/reference.md")

const testPass = "a long enough test passphrase"

func TestMain(m *testing.M) {
	kdf.Default = kdf.Cost{Mem: kdf.MinMem, Time: 1, Par: 1}
	passphrase.Prompt = func(string) ([]byte, error) { return nil, errors.New("test must not prompt") }
	passphrase.Keychain = func(string) ([]byte, error) { return nil, errors.New("test must not reach the keychain") }
	promptSecret = func(string) ([]byte, error) { return nil, errors.New("test must not prompt") }
	for _, v := range []string{"KEYSTORE_KEYCHAIN", "KEYSTORE_PASSPHRASE", "KEYSTORE_NEW_PASSPHRASE", "KEYSTORE_FILE"} {
		os.Unsetenv(v)
	}
	os.Exit(m.Run())
}

// cli runs one invocation in-process and returns stdout, stderr and the error.
func cli(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	return cliIn(t, "", args...)
}

func cliIn(t *testing.T, stdin string, args ...string) (string, string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	err := run(args, &stdio{in: strings.NewReader(stdin), out: &out, err: &errb})
	return out.String(), errb.String(), err
}

func ring(t *testing.T) string {
	t.Helper()
	t.Setenv("KEYSTORE_PASSPHRASE", testPass)
	return filepath.Join(t.TempDir(), "r.ks")
}

func TestKeygenListExportPub(t *testing.T) {
	r := ring(t)
	out, _, err := cli(t, "keygen", "-keystore", r, "-id", "prod")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := keystore.ParsePublicKeyPEM([]byte(out))
	if err != nil {
		t.Fatalf("keygen stdout is not a public key PEM: %v\n%s", err, out)
	}
	exp, _, err := cli(t, "export-pub", "-keystore", r)
	if err != nil || exp != out {
		t.Fatalf("export-pub = %q, %v; want keygen's PEM", exp, err)
	}
	list, _, err := cli(t, "list", "-keystore", r)
	if err != nil || !strings.HasPrefix(list, "*  prod  ed25519") || !strings.Contains(list, keystore.Fingerprint(pub)) {
		t.Fatalf("list = %q, %v", list, err)
	}
}

func TestListAndExportPubNeedNoPassphrase(t *testing.T) {
	r := ring(t)
	cli(t, "keygen", "-keystore", r, "-id", "a")
	t.Setenv("KEYSTORE_PASSPHRASE", "") // and Prompt fails the test if called
	if _, _, err := cli(t, "list", "-keystore", r); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cli(t, "export-pub", "-keystore", r, "-id", "a"); err != nil {
		t.Fatal(err)
	}
}

func TestNewPassphraseLengthOnlyWhenEstablishing(t *testing.T) {
	r := ring(t)
	t.Setenv("KEYSTORE_PASSPHRASE", "short")
	if _, _, err := cli(t, "keygen", "-keystore", r, "-id", "a"); !errors.Is(err, passphrase.ErrTooShort) {
		t.Fatalf("short new passphrase: %v", err)
	}
	if _, err := os.Stat(r); err != nil {
		t.Fatalf("keygen should still have created the empty ring: %v", err)
	}
	t.Setenv("KEYSTORE_PASSPHRASE", testPass)
	if _, _, err := cli(t, "add", "-keystore", r, "-id", "a"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYSTORE_PASSPHRASE", "short")
	if _, _, err := cli(t, "add", "-keystore", r, "-id", "b"); !errors.Is(err, keystore.ErrPassphraseMismatch) {
		t.Fatalf("existing ring, wrong short passphrase: %v (want mismatch, not a length error)", err)
	}
}

func TestInitNeverOverwrites(t *testing.T) {
	r := ring(t)
	cli(t, "keygen", "-keystore", r, "-id", "a")
	before, _ := os.ReadFile(r)
	if _, _, err := cli(t, "init", "-keystore", r); err == nil {
		t.Fatal("init over an existing ring succeeded")
	}
	after, _ := os.ReadFile(r)
	if !bytes.Equal(before, after) {
		t.Fatal("init modified an existing ring")
	}
}

func TestImportUseRm(t *testing.T) {
	r := ring(t)
	cli(t, "keygen", "-keystore", r, "-id", "a")
	_, priv, _ := ed25519.GenerateKey(nil)
	pemB, _ := keystore.MarshalPrivateKeyPEM(priv)
	kf := filepath.Join(t.TempDir(), "k.pem")
	os.WriteFile(kf, pemB, 0o600)
	if _, _, err := cli(t, "import", "-keystore", r, "-id", "b", "-key", kf); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cli(t, "use", "-keystore", r, "-id", "b"); err != nil {
		t.Fatal(err)
	}
	pubOut, _, _ := cli(t, "export-pub", "-keystore", r)
	if pub, _ := keystore.ParsePublicKeyPEM([]byte(pubOut)); !pub.Equal(priv.Public()) {
		t.Fatal("current is not the imported key after use")
	}
	if _, _, err := cli(t, "rm", "-keystore", r, "-id", "b"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cli(t, "rm", "-keystore", r, "-id", "a"); !errors.Is(err, keystore.ErrLastSigningKey) {
		t.Fatalf("rm last key without -force: %v", err)
	}
	if _, _, err := cli(t, "rm", "-keystore", r, "-id", "a", "-force"); err != nil {
		t.Fatal(err)
	}
}

func TestExportPrivFileRules(t *testing.T) {
	r := ring(t)
	cli(t, "keygen", "-keystore", r, "-id", "a")
	dir := t.TempDir()

	// New file: created 0600 and holds the key.
	nf := filepath.Join(dir, "new.pem")
	if _, _, err := cli(t, "export-priv", "-keystore", r, "-o", nf); err != nil {
		t.Fatal(err)
	}
	assertMode(t, nf, 0o600)
	b, _ := os.ReadFile(nf)
	if _, err := keystore.ParsePrivateKeyPEM(b); err != nil {
		t.Fatalf("exported file is not a private key: %v", err)
	}

	// Existing 0644 file: refused and untouched; with -force replaced and 0600.
	ex := filepath.Join(dir, "existing.pem")
	os.WriteFile(ex, []byte("old"), 0o644)
	if _, _, err := cli(t, "export-priv", "-keystore", r, "-o", ex); err == nil {
		t.Fatal("overwrote an existing file without -force")
	}
	if got, _ := os.ReadFile(ex); string(got) != "old" {
		t.Fatal("refused export still modified the file")
	}
	assertMode(t, ex, 0o644)
	if _, _, err := cli(t, "export-priv", "-keystore", r, "-o", ex, "-force"); err != nil {
		t.Fatal(err)
	}
	assertMode(t, ex, 0o600)

	// Symlink: refused, with or without -force, and the target is untouched.
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("victim"), 0o644)
	link := filepath.Join(dir, "link.pem")
	os.Symlink(target, link)
	for _, extra := range [][]string{nil, {"-force"}} {
		args := append([]string{"export-priv", "-keystore", r, "-o", link}, extra...)
		if _, _, err := cli(t, args...); err == nil {
			t.Fatalf("wrote through a symlink (%v)", extra)
		}
	}
	if got, _ := os.ReadFile(target); string(got) != "victim" {
		t.Fatal("symlink target was modified")
	}
	// Dangling symlink: O_EXCL|O_NOFOLLOW must not create the target.
	dangling := filepath.Join(dir, "dangling.pem")
	os.Symlink(filepath.Join(dir, "created-through-link"), dangling)
	cli(t, "export-priv", "-keystore", r, "-o", dangling)
	if _, err := os.Stat(filepath.Join(dir, "created-through-link")); err == nil {
		t.Fatal("export created a file through a dangling symlink")
	}
}

func TestExportPrivRefusesTerminal(t *testing.T) {
	r := ring(t)
	cli(t, "keygen", "-keystore", r, "-id", "a")
	old := isTerminal
	isTerminal = func(*os.File) bool { return true }
	defer func() { isTerminal = old }()
	fake, _ := os.CreateTemp(t.TempDir(), "tty")
	defer fake.Close()
	var out bytes.Buffer
	err := run([]string{"export-priv", "-keystore", r}, &stdio{out: &out, err: &out, outFile: fake})
	if err == nil || out.Len() != 0 {
		t.Fatalf("export-priv to a terminal: %v, wrote %d bytes", err, out.Len())
	}
	out.Reset()
	err = run([]string{"export-priv", "-keystore", r, "-force"}, &stdio{out: &out, err: io.Discard, outFile: fake})
	if err != nil || !strings.Contains(out.String(), "PRIVATE KEY") {
		t.Fatalf("export-priv -force to a terminal: %v", err)
	}
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"nope"},
		{"add"},                         // missing -id
		{"list", "extra-arg"},           // stray argument
		{"list", "-passphrase", "oops"}, // there is no passphrase flag
	}
	for _, args := range cases {
		if _, _, err := cli(t, args...); !isUsage(err) {
			t.Errorf("%v: err = %v, want a usage error", args, err)
		}
	}
}

func TestNoVerbHasAPassphraseFlag(t *testing.T) {
	for _, v := range verbs {
		fs := flag.NewFlagSet(v.name, flag.ContinueOnError)
		v.setup(fs, &stdio{})
		fs.VisitAll(func(f *flag.Flag) {
			if strings.Contains(strings.ToLower(f.Name), "pass") && !strings.HasSuffix(f.Name, "passfile") {
				t.Errorf("verb %s has flag -%s", v.name, f.Name)
			}
		})
	}
}

// TestReference fails if docs/reference.md and the verb table disagree in either
// direction. -update rewrites the file.
func TestReference(t *testing.T) {
	var b bytes.Buffer
	writeReference(&b)
	const path = "../../docs/reference.md"
	if *update {
		if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, b.Bytes()) {
		t.Fatal("docs/reference.md is out of date with the verb table; run: go test ./cmd/keystore -run TestReference -args -update")
	}
	for _, line := range strings.Split(string(got), "\n") {
		if name, ok := strings.CutPrefix(line, "## `"); ok {
			name = strings.TrimSuffix(name, "`")
			if !hasVerb(name) {
				t.Errorf("reference documents verb %q that does not exist", name)
			}
		}
	}
}

func hasVerb(name string) bool {
	for _, v := range verbs {
		if v.name == name {
			return true
		}
	}
	return false
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != want {
		t.Fatalf("%s mode %v, want %v", filepath.Base(path), st.Mode().Perm(), want)
	}
}

func TestImportKeySizeCap(t *testing.T) {
	r := ring(t)
	big := filepath.Join(t.TempDir(), "big.pem")
	os.WriteFile(big, bytes.Repeat([]byte("A"), 128<<10), 0o600)
	if _, _, err := cli(t, "import", "-keystore", r, "-id", "x", "-key", big); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversize key file: %v", err)
	}
}

// A file name the operator's script passes through can carry terminal control sequences
// (recolour, retitle, a carriage return back over the line start to forge a "keystore:
// verified" line, a bidi override that reorders the rest of the line). Nothing the CLI
// prints may let them act: not in a failure message, and not in the success-path lines
// that echo an output or input path either.
const hostile = "a\x1b[31m\x1b]0;pwned\x07\rkeystore: verified: SHA256:fake\x7f\u009b\u202e\u2028b"

func assertInert(t *testing.T, what, text string) {
	t.Helper()
	for _, r := range text {
		if r != '\n' && r != '\t' && !unicode.IsPrint(r) { // layout of the usage text is ours
			t.Errorf("%s: terminal-active rune %U survives in %q", what, r, text)
			return
		}
	}
}

func TestOneLineNeutralisesControlCharacters(t *testing.T) {
	got := oneLine(fmt.Errorf("open %s: no such file or directory", hostile+"\xff"))
	assertInert(t, "oneLine", got)
	if !strings.Contains(got, "no such file or directory") || !strings.HasPrefix(got, "keystore: ") {
		t.Errorf("message mangled: %q", got)
	}
}

func TestSuccessLinesEchoNoTerminalControls(t *testing.T) {
	r, _, msg := signFixture(t)
	dir := t.TempDir()

	_, errOut, err := cli(t, "sign", "-keystore", r, "-in", msg, "-o", filepath.Join(dir, hostile+".sig"))
	if err != nil {
		t.Fatal(err)
	}
	assertInert(t, "sign -o", errOut)

	_, errOut, err = cli(t, "export-priv", "-keystore", r, "-o", filepath.Join(dir, hostile+".pem"))
	if err != nil {
		t.Fatal(err)
	}
	assertInert(t, "export-priv -o", errOut)

	_, priv, _ := ed25519.GenerateKey(nil)
	pemB, _ := keystore.MarshalPrivateKeyPEM(priv)
	kf := filepath.Join(dir, hostile+".in")
	if err := os.WriteFile(kf, pemB, 0o600); err != nil {
		t.Fatal(err)
	}
	_, errOut, err = cli(t, "import", "-keystore", r, "-id", "b", "-key", kf)
	if err != nil {
		t.Fatal(err)
	}
	assertInert(t, "import -key", errOut)
}

func TestInitAndPasswdEchoNoTerminalControls(t *testing.T) {
	t.Setenv("KEYSTORE_PASSPHRASE", testPass)
	_, errOut, err := cli(t, "init", "-keystore", filepath.Join(t.TempDir(), hostile+".ks"))
	if err != nil {
		t.Fatal(err)
	}
	assertInert(t, "init", errOut)

	r, _, _ := signFixture(t)
	t.Setenv("KEYSTORE_NEW_PASSPHRASE", "a different long passphrase")
	t.Setenv("KEYSTORE_KEYCHAIN", hostile) // names the item the operator keeps the passphrase in
	_, errOut, err = cli(t, "passwd", "-keystore", r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut, "keychain-set -service") {
		t.Fatalf("passwd did not print the keychain note: %q", errOut)
	}
	assertInert(t, "passwd note", errOut)
}

// The flag package echoes an unknown flag name verbatim, and a script that lets a file
// name become a flag token (`keystore sign "$f"`) hands it attacker bytes. Both copies of
// the message (the flag package's own, and the usage error main prints) must be inert.
func TestUnknownFlagNameIsInert(t *testing.T) {
	_, errOut, err := cli(t, "sign", "-"+hostile)
	if err == nil || !isUsage(err) {
		t.Fatalf("err = %v, want a usage error", err)
	}
	assertInert(t, "flag package output", errOut)
	var b bytes.Buffer
	if code := report(&b, err); code != 2 {
		t.Errorf("report code %d, want 2", code)
	}
	assertInert(t, "usage error line", b.String())
}

// A newline inside an unknown flag name used to start a new line of the flag package's
// own message, so a name beginning with '-' could forge a whole "keystore: verified" line.
func TestNewlineInFlagNameCannotForgeALine(t *testing.T) {
	_, errOut, err := cli(t, "sign", "-a\nkeystore: verified: SHA256:FORGED")
	if err == nil || !isUsage(err) {
		t.Fatalf("err = %v, want a usage error", err)
	}
	var b bytes.Buffer
	report(&b, err)
	for _, text := range []string{errOut, b.String()} {
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "keystore: verified") {
				t.Errorf("forged line %q in %q", line, text)
			}
		}
	}
	if !strings.Contains(errOut, "-keystore") {
		t.Errorf("usage text no longer printed for a mistyped flag: %q", errOut)
	}
}

func TestReportExitCodesAndCleaning(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{
		{nil, 0},
		{flag.ErrHelp, 0},
		{usageError("bad " + hostile), 2},
		{errors.New("open " + hostile + ": no such file"), 1},
	} {
		var b bytes.Buffer
		if code := report(&b, tc.err); code != tc.code {
			t.Errorf("report(%v) = %d, want %d", tc.err, code, tc.code)
		}
		assertInert(t, "report", b.String())
	}
}
