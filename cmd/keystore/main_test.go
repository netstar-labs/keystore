package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
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

// `export-priv > key.pem` lets the shell create the file at the umask mode (0644 under
// the usual 022) before keystore runs, so the plaintext key landed in a file others
// could read: the terminal guard did not cover it and only -o enforces 0600.
func TestExportRefusesRedirectToAFileOthersCanRead(t *testing.T) {
	r := ring(t)
	if _, _, err := cli(t, "keygen", "-keystore", r, "-id", "a"); err != nil {
		t.Fatal(err)
	}
	for _, verb := range [][]string{{"export-priv", "-keystore", r}, {"export-secret", "-keystore", r}} {
		if verb[0] == "export-secret" {
			if _, _, err := cli(t, "add-secret", "-keystore", r, "-id", "s"); err != nil {
				t.Fatal(err)
			}
			verb = append(verb, "-id", "s")
		}
		for _, tc := range []struct {
			mode  os.FileMode
			force bool
			ok    bool
		}{
			{0o644, false, false}, {0o640, false, false}, {0o604, false, false},
			{0o620, false, false}, {0o602, false, false}, // writable by others is not private either
			{0o600, false, true}, {0o400 | 0o200, false, true},
			{0o644, true, true}, // -force is the same deliberate override as for a terminal
		} {
			f, err := os.CreateTemp(t.TempDir(), "redir")
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Chmod(tc.mode); err != nil {
				t.Fatal(err)
			}
			args := append([]string(nil), verb...)
			if tc.force {
				args = append(args, "-force")
			}
			var errb bytes.Buffer
			err = run(args, &stdio{in: strings.NewReader(""), out: f, err: &errb, inFile: nil, outFile: f})
			st, _ := f.Stat()
			f.Close()
			if tc.ok && err != nil {
				t.Errorf("%s into a %04o file (force=%v): %v", verb[0], tc.mode, tc.force, err)
			}
			if !tc.ok {
				if err == nil || !strings.Contains(err.Error(), "others can read") {
					t.Errorf("%s into a %04o file: err = %v, want a refusal", verb[0], tc.mode, err)
				}
				if st.Size() != 0 {
					t.Errorf("%s wrote %d bytes into a refused %04o file", verb[0], st.Size(), tc.mode)
				}
			}
		}
	}
	// With -o the key goes to that file (0600), so what stdout is does not matter.
	loose, _ := os.CreateTemp(t.TempDir(), "loose")
	loose.Chmod(0o644)
	out := filepath.Join(t.TempDir(), "k.pem")
	if err := run([]string{"export-priv", "-keystore", r, "-o", out}, &stdio{in: strings.NewReader(""), out: loose, err: io.Discard, outFile: loose}); err != nil {
		t.Errorf("-o with a loose stdout refused: %v", err)
	}
	loose.Close()
	// A pipe has no mode to check: the user chose where the bytes go.
	pr, pw, _ := os.Pipe()
	defer pr.Close()
	defer pw.Close()
	if err := run([]string{"export-priv", "-keystore", r}, &stdio{in: strings.NewReader(""), out: pw, err: io.Discard, outFile: pw}); err != nil {
		t.Errorf("export-priv into a pipe refused: %v", err)
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
		{errBadSig, 3},
		{fmt.Errorf("verify: %w", errBadSig), 3},
		{errors.New("open " + hostile + ": no such file"), 1},
	} {
		var b bytes.Buffer
		if code := report(&b, tc.err); code != tc.code {
			t.Errorf("report(%v) = %d, want %d", tc.err, code, tc.code)
		}
		assertInert(t, "report", b.String())
	}
}

// Automation that gates on `keystore verify` needs to tell "this signature is bad" from
// "could not check" (a missing file, an unreadable key, usage): they shared exit 1.
func TestVerifyExitCodeDistinguishesABadSignature(t *testing.T) {
	r, pub, msg := signFixture(t)
	sig := filepath.Join(t.TempDir(), "m.sig")
	if _, _, err := cli(t, "sign", "-keystore", r, "-in", msg, "-o", sig); err != nil {
		t.Fatal(err)
	}
	status := func(args ...string) int {
		t.Helper()
		_, _, err := cli(t, args...)
		return report(io.Discard, err)
	}
	if got := status("verify", "-pub", pub, "-sig", sig, "-in", msg); got != 0 {
		t.Fatalf("good signature: status %d, want 0", got)
	}
	b, _ := os.ReadFile(sig)
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	raw[0] ^= 1
	bad := filepath.Join(t.TempDir(), "bad.sig")
	os.WriteFile(bad, []byte(base64.StdEncoding.EncodeToString(raw)), 0o644)
	if got := status("verify", "-pub", pub, "-sig", bad, "-in", msg); got != 3 {
		t.Errorf("bad signature: status %d, want 3", got)
	}
	other := filepath.Join(t.TempDir(), "other")
	os.WriteFile(other, []byte("a different message"), 0o644)
	if got := status("verify", "-pub", pub, "-sig", sig, "-in", other); got != 3 {
		t.Errorf("signature for another message: status %d, want 3", got)
	}
	for name, tc := range map[string]struct {
		args []string
		want int
	}{
		"missing sig file": {[]string{"verify", "-pub", pub, "-sig", filepath.Join(t.TempDir(), "none"), "-in", msg}, 1},
		"missing pub file": {[]string{"verify", "-pub", filepath.Join(t.TempDir(), "none"), "-sig", sig, "-in", msg}, 1},
		"junk signature":   {[]string{"verify", "-pub", pub, "-sig", pub, "-in", msg}, 1},
		"usage":            {[]string{"verify", "-pub", pub}, 2},
	} {
		if got := status(tc.args...); got != tc.want {
			t.Errorf("%s: status %d, want %d", name, got, tc.want)
		}
	}
}

// With no -keystore, no KEYSTORE_FILE and no home directory (cron, a system unit) the ring
// path silently became ./default.ks: keygen exited 0 and left a ring in the working directory
// that the next command, run from anywhere else, could not find.
func TestNoRingPathWithoutHomeIsAUsageErrorNotACwdRing(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	t.Setenv("HOME", "")
	t.Setenv("KEYSTORE_FILE", "")
	t.Setenv("KEYSTORE_PASSPHRASE", testPass)
	for _, verb := range []string{"init", "keygen", "add", "import", "list", "use", "rm", "export-pub", "export-priv", "sign", "add-secret", "import-secret", "export-secret", "passwd"} {
		args := []string{verb}
		if verb != "init" && verb != "list" && verb != "export-pub" && verb != "sign" && verb != "passwd" {
			args = append(args, "-id", "a")
		}
		_, _, err := cli(t, args...)
		if !isUsage(err) || !strings.Contains(err.Error(), "-keystore") || !strings.Contains(err.Error(), "KEYSTORE_FILE") {
			t.Errorf("%s with no ring path and no HOME: err = %v, want a usage error naming -keystore and KEYSTORE_FILE", verb, err)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(cwd, "*")); len(left) != 0 {
		t.Errorf("a ring was created in the working directory: %v", left)
	}
	// An explicit path, or KEYSTORE_FILE, still works without a home directory.
	if _, _, err := cli(t, "init", "-keystore", filepath.Join(cwd, "explicit.ks")); err != nil {
		t.Errorf("explicit -keystore without HOME: %v", err)
	}
	t.Setenv("KEYSTORE_FILE", filepath.Join(cwd, "env.ks"))
	if _, _, err := cli(t, "init"); err != nil {
		t.Errorf("KEYSTORE_FILE without HOME: %v", err)
	}
	// sign -agent never reads the ring, so no home directory is no obstacle: it must get past
	// the ring-path check (here it fails later, dialing a socket nobody listens on).
	t.Setenv("KEYSTORE_FILE", "")
	if _, _, err := cli(t, "sign", "-agent", filepath.Join(cwd, "none.sock")); err == nil || isUsage(err) {
		t.Errorf("sign -agent without HOME: err = %v, want a non-usage failure from the dial", err)
	}
	// Verbs with no ring flag are unaffected.
	// (keychain-set gets an invalid service so that it is refused before it can run the
	// real security(1) and touch the developer's login keychain.)
	for _, args := range [][]string{{"verify"}, {"keychain-set", "-service", "-w"}} {
		if _, _, err := cli(t, args...); err != nil && strings.Contains(err.Error(), "no ring path") {
			t.Errorf("%s: %v", args[0], err)
		}
	}
	// An explicit empty path is refused even with a home directory.
	t.Setenv("HOME", cwd)
	for _, a := range [][]string{{"list", "-keystore", ""}, {"list", "-keystore="}} {
		if _, _, err := cli(t, a...); !isUsage(err) || !strings.Contains(err.Error(), "no ring path") {
			t.Errorf("%v: err = %v, want the no-ring-path usage error", a, err)
		}
	}
}
