package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/netstar-labs/keystore/pkg/keystore"
)

// Error paths of the verbs. Each case asserts what the operator would see (a usage error
// or a failure, never a success line) and that nothing was written.

// errFixture is a ring holding a signing key "a" and a secret "s", plus the files the
// verbs read. The passphrase is in KEYSTORE_PASSPHRASE until a test clears it.
type errFixture struct {
	ring, keyPEM, secretFile, msg, dir string
}

func newErrFixture(t *testing.T) errFixture {
	t.Helper()
	r := ring(t)
	if _, _, err := cli(t, "keygen", "-keystore", r, "-id", "a"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cli(t, "add-secret", "-keystore", r, "-id", "s"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(nil)
	pemB, _ := keystore.MarshalPrivateKeyPEM(priv)
	f := errFixture{ring: r, dir: dir,
		keyPEM:     filepath.Join(dir, "k.pem"),
		secretFile: filepath.Join(dir, "s.b64"),
		msg:        filepath.Join(dir, "msg")}
	for path, content := range map[string][]byte{
		f.keyPEM:     pemB,
		f.secretFile: []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) + "\n"),
		f.msg:        []byte("message"),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// ringVerbs lists, for every verb that opens an existing ring, an invocation that is
// valid but for the ring (and, in unlockVerbs, the passphrase).
func (f errFixture) ringVerbs(ring string) map[string][]string {
	return map[string][]string{
		"add":           {"add", "-keystore", ring, "-id", "n"},
		"import":        {"import", "-keystore", ring, "-id", "n", "-key", f.keyPEM},
		"list":          {"list", "-keystore", ring},
		"use":           {"use", "-keystore", ring, "-id", "a"},
		"rm":            {"rm", "-keystore", ring, "-id", "a", "-force"},
		"export-pub":    {"export-pub", "-keystore", ring},
		"export-priv":   {"export-priv", "-keystore", ring, "-id", "a"},
		"add-secret":    {"add-secret", "-keystore", ring, "-id", "n"},
		"import-secret": {"import-secret", "-keystore", ring, "-id", "n", "-in", f.secretFile},
		"export-secret": {"export-secret", "-keystore", ring, "-id", "s"},
		"passwd":        {"passwd", "-keystore", ring},
		"sign":          {"sign", "-keystore", ring, "-in", f.msg},
	}
}

func TestVerbsRefuseAMissingIDBeforeTouchingAnything(t *testing.T) {
	r := ring(t) // does not exist: a verb that got past need() would fail differently, or create it
	for _, args := range [][]string{
		{"keygen"}, {"add"}, {"import", "-key", "k"}, {"use"}, {"rm"},
		{"add-secret"}, {"import-secret"}, {"export-secret"},
	} {
		out, _, err := cli(t, append([]string{args[0], "-keystore", r}, args[1:]...)...)
		if !isUsage(err) || !strings.Contains(err.Error(), "-id is required") {
			t.Errorf("%v: err = %v, want a usage error naming -id", args, err)
		}
		if out != "" {
			t.Errorf("%v: wrote %q to stdout", args, out)
		}
	}
	if _, err := os.Stat(r); err == nil {
		t.Error("keygen without -id created the ring")
	}
	if _, _, err := cli(t, "import", "-keystore", r, "-id", "x"); !isUsage(err) || !strings.Contains(err.Error(), "-key is required") {
		t.Errorf("import without -key: %v", err)
	}
}

func TestVerbsOnAMissingRingFailAndCreateNothing(t *testing.T) {
	f := newErrFixture(t)
	missing := filepath.Join(f.dir, "no", "such.ks")
	for name, args := range f.ringVerbs(missing) {
		out, _, err := cli(t, args...)
		if err == nil || isUsage(err) || !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: err = %v, want a not-exist failure", name, err)
		}
		if out != "" {
			t.Errorf("%s: wrote %q to stdout", name, out)
		}
	}
	if _, err := os.Stat(filepath.Dir(missing)); err == nil {
		t.Error("a verb created the missing ring's directory")
	}
}

// An explicit -passfile that cannot be read is an error: the verb must not fall back to
// prompting (which the harness would fail) or to anything else, and must leave the ring
// as it was.
func TestMissingPassfileFailsAndLeavesTheRingUntouched(t *testing.T) {
	f := newErrFixture(t)
	t.Setenv("KEYSTORE_PASSPHRASE", "")
	before, _ := os.ReadFile(f.ring)
	pf := filepath.Join(f.dir, "no-such-passfile")
	for name, args := range f.ringVerbs(f.ring) {
		if name == "list" || name == "use" || name == "rm" || name == "export-pub" {
			continue // these never ask for a passphrase
		}
		args = append(args, "-passfile", pf)
		if name == "passwd" {
			args = append(args, "-new-passfile", pf)
		}
		out, _, err := cli(t, args...)
		if err == nil || !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: err = %v, want the passfile's not-exist error", name, err)
		}
		if out != "" {
			t.Errorf("%s: wrote %q to stdout", name, out)
		}
	}
	if after, _ := os.ReadFile(f.ring); !bytes.Equal(before, after) {
		t.Error("a failed passphrase lookup modified the ring")
	}
}

func TestPasswdFailsOnAMissingNewPassfile(t *testing.T) {
	f := newErrFixture(t)
	before, _ := os.ReadFile(f.ring)
	_, _, err := cli(t, "passwd", "-keystore", f.ring, "-new-passfile", filepath.Join(f.dir, "nope"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("passwd with a missing -new-passfile: %v", err)
	}
	if after, _ := os.ReadFile(f.ring); !bytes.Equal(before, after) {
		t.Error("passwd changed the ring although the new passphrase could not be read")
	}
}

func readOnlyDir(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	d := t.TempDir()
	if err := os.Chmod(d, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(d, 0o700) }) // runs before TempDir's own removal
	return d
}

func TestWriteFailuresInAReadOnlyDirectory(t *testing.T) {
	f := newErrFixture(t)
	ro := readOnlyDir(t)
	for name, args := range map[string][]string{
		"init":        {"init", "-keystore", filepath.Join(ro, "r.ks")},
		"keygen":      {"keygen", "-keystore", filepath.Join(ro, "r.ks"), "-id", "a"},
		"sign -o":     {"sign", "-keystore", f.ring, "-in", f.msg, "-o", filepath.Join(ro, "sig")},
		"export-priv": {"export-priv", "-keystore", f.ring, "-id", "a", "-o", filepath.Join(ro, "k.pem")},
		"export-sec":  {"export-secret", "-keystore", f.ring, "-id", "s", "-o", filepath.Join(ro, "s.b64")},
	} {
		out, errOut, err := cli(t, args...)
		if !errors.Is(err, fs.ErrPermission) {
			t.Errorf("%s: err = %v, want a permission error", name, err)
		}
		if out != "" || strings.Contains(errOut, "wrote ") || strings.Contains(errOut, "created ") {
			t.Errorf("%s: reported success: stdout %q stderr %q", name, out, errOut)
		}
	}
	if ents, _ := os.ReadDir(ro); len(ents) != 0 {
		t.Errorf("failed writes left files behind: %v", ents)
	}
}

// -force replaces by temp-and-rename; when the temp file cannot be made the old file is
// what remains, whole.
func TestForceReplaceFailureKeepsTheOldFile(t *testing.T) {
	f := newErrFixture(t)
	d := t.TempDir()
	sig := filepath.Join(d, "sig")
	if _, _, err := cli(t, "sign", "-keystore", f.ring, "-in", f.msg, "-o", sig); err != nil {
		t.Fatal(err)
	}
	old, _ := os.ReadFile(sig)
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	os.Chmod(d, 0o500)
	defer os.Chmod(d, 0o700)
	if _, _, err := cli(t, "sign", "-keystore", f.ring, "-in", f.msg, "-o", sig, "-force"); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("err = %v, want a permission error", err)
	}
	if now, _ := os.ReadFile(sig); !bytes.Equal(old, now) {
		t.Fatal("a failed replace damaged the existing file")
	}
	if ents, _ := os.ReadDir(d); len(ents) != 1 {
		t.Errorf("a failed replace left a temp file behind: %v", ents)
	}
}

func TestOutputPathRefusals(t *testing.T) {
	f := newErrFixture(t)
	file := filepath.Join(f.dir, "plain")
	os.WriteFile(file, []byte("x"), 0o600)
	dir := filepath.Join(f.dir, "adir")
	os.Mkdir(dir, 0o700)
	for _, tc := range []struct {
		name, out string
		force     bool
		want      error  // errors.Is target, or nil
		text      string // substring otherwise
	}{
		{"parent is a regular file", filepath.Join(file, "sub"), false, syscall.ENOTDIR, ""},
		{"directory, even with -force", dir, true, nil, "not a regular file"},
		{"exists without -force", file, false, nil, "refusing to overwrite"},
	} {
		_, _, err := cli(t, "export-priv", "-keystore", f.ring, "-id", "a", "-o", tc.out, "-passfile", "", "-force="+map[bool]string{true: "true", false: "false"}[tc.force])
		if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) || (tc.text != "" && !strings.Contains(err.Error(), tc.text)) {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
	if b, _ := os.ReadFile(file); string(b) != "x" {
		t.Errorf("an existing file was changed: %q", b)
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Error("the directory was replaced")
	}
}

// A dead -agent is an error. It must not fall back to the ring, even though the ring and
// its passphrase are right there: the operator asked for the agent.
func TestSignAgentDialFailureDoesNotFallBackToTheRing(t *testing.T) {
	f := newErrFixture(t)
	short, err := os.MkdirTemp("/tmp", "ks")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(short)
	stale := filepath.Join(short, "stale.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	ln.Close() // leaves a socket file nobody answers on
	notSocket := filepath.Join(short, "file")
	os.WriteFile(notSocket, []byte("x"), 0o600)

	for name, sock := range map[string]string{
		"absent": filepath.Join(short, "absent.sock"), "stale socket": stale, "not a socket": notSocket,
	} {
		out, errOut, err := cli(t, "sign", "-agent", sock, "-keystore", f.ring, "-in", f.msg)
		if err == nil || isUsage(err) {
			t.Errorf("%s: err = %v, want a connection failure", name, err)
		}
		if out != "" || strings.Contains(errOut, "signing with") {
			t.Errorf("%s: signed anyway: stdout %q stderr %q", name, out, errOut)
		}
	}
}

func TestVerifyInputErrors(t *testing.T) {
	f := newErrFixture(t)
	pubOut, _, _ := cli(t, "export-pub", "-keystore", f.ring)
	pub := filepath.Join(f.dir, "pub.pem")
	os.WriteFile(pub, []byte(pubOut), 0o644)
	sigOut, _, err := cli(t, "sign", "-keystore", f.ring, "-in", f.msg)
	if err != nil {
		t.Fatal(err)
	}
	sig := filepath.Join(f.dir, "sig")
	os.WriteFile(sig, []byte(sigOut), 0o644)
	junk := filepath.Join(f.dir, "junk")
	os.WriteFile(junk, []byte("not a pem"), 0o644)
	gone := filepath.Join(f.dir, "gone")

	for _, tc := range []struct {
		name  string
		args  []string
		usage bool
		is    error
	}{
		{"no -pub", []string{"-sig", sig, "-in", f.msg}, true, nil},
		{"no -sig", []string{"-pub", pub, "-in", f.msg}, true, nil},
		{"pub not PEM", []string{"-pub", junk, "-sig", sig, "-in", f.msg}, false, nil},
		{"pub missing", []string{"-pub", gone, "-sig", sig, "-in", f.msg}, false, fs.ErrNotExist},
		{"sig missing", []string{"-pub", pub, "-sig", gone, "-in", f.msg}, false, fs.ErrNotExist},
		{"sig is junk", []string{"-pub", pub, "-sig", junk, "-in", f.msg}, false, nil},
		{"message missing", []string{"-pub", pub, "-sig", sig, "-in", gone}, false, fs.ErrNotExist},
	} {
		_, errOut, err := cli(t, append([]string{"verify"}, tc.args...)...)
		if err == nil || isUsage(err) != tc.usage || (tc.is != nil && !errors.Is(err, tc.is)) {
			t.Errorf("%s: err = %v (usage=%v)", tc.name, err, isUsage(err))
		}
		if errors.Is(err, errBadSig) || strings.Contains(errOut, "verified") {
			t.Errorf("%s: an input error was reported as a verification result: %v / %q", tc.name, err, errOut)
		}
	}
	if _, _, err := cli(t, "sign", "-keystore", f.ring, "-in", gone); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("sign with a missing message: %v", err)
	}
}

func TestHelpAndVersionVerbs(t *testing.T) {
	for _, a := range []string{"help", "-h", "-help", "--help"} {
		out, errOut, err := cli(t, a)
		if err != nil || !strings.Contains(out, "usage: keystore <verb>") || errOut != "" {
			t.Errorf("%s: out %q err %q %v", a, out, errOut, err)
		}
		for _, v := range verbs {
			if !strings.Contains(out, v.name) {
				t.Errorf("%s: verb %s missing from the help", a, v.name)
			}
		}
	}
	old, oldB := version, build
	version, build = "v9.9.9", "abc123"
	defer func() { version, build = old, oldB }()
	for _, a := range []string{"version", "-version", "--version"} {
		if out, _, err := cli(t, a); err != nil || out != "keystore v9.9.9 (abc123)\n" {
			t.Errorf("%s: %q, %v", a, out, err)
		}
	}
}

// A verb's own -h prints its flags on stderr and is not a failure.
func TestVerbHelpIsNotAnError(t *testing.T) {
	out, errOut, err := cli(t, "list", "-h")
	if !errors.Is(err, flag.ErrHelp) || report(&bytes.Buffer{}, err) != 0 {
		t.Fatalf("list -h: %v", err)
	}
	if out != "" || !strings.Contains(errOut, "keystore list") || !strings.Contains(errOut, "-keystore") {
		t.Fatalf("list -h: stdout %q stderr %q", out, errOut)
	}
}

func TestDefaultRingResolution(t *testing.T) {
	t.Setenv("KEYSTORE_FILE", "")
	t.Setenv("HOME", "")
	if got := defaultRing(); got != "" {
		t.Errorf("no home: defaultRing() = %q, want empty (callers refuse an empty ring path)", got)
	}
	t.Setenv("HOME", "/home/someone")
	if got := defaultRing(); got != "/home/someone/.config/keystore/default.ks" {
		t.Errorf("defaultRing() = %q", got)
	}
}

// Only the default ring's directory is created, and owner-only; for an explicit path the
// caller owns the directory.
func TestDefaultRingDirectoryIsCreatedOwnerOnly(t *testing.T) {
	base := t.TempDir()
	def := filepath.Join(base, "cfg", "keystore", "default.ks")
	t.Setenv("KEYSTORE_FILE", def)
	if _, _, err := cli(t, "init"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Dir(def))
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("default ring dir: %v, %v; want 0700", st, err)
	}
	// explicit path in a directory that does not exist: not created, init fails
	if _, _, err := cli(t, "init", "-keystore", filepath.Join(base, "other", "x.ks")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("explicit ring in a missing directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "other")); err == nil {
		t.Error("an explicit ring path's directory was created")
	}
	// the default path under a regular file: the directory cannot be made
	blocker := filepath.Join(base, "blocker")
	os.WriteFile(blocker, nil, 0o600)
	t.Setenv("KEYSTORE_FILE", filepath.Join(blocker, "d", "r.ks"))
	if _, _, err := cli(t, "keygen", "-id", "a"); !errors.Is(err, syscall.ENOTDIR) {
		t.Errorf("keygen with an unmakeable default directory: %v", err)
	}
}

// keychain-set validates the service name before it runs anything (on macOS), and says
// nothing about success when it fails (everywhere: other platforms report unsupported).
func TestKeychainSetFailureReportsNoSuccess(t *testing.T) {
	_, errOut, err := cli(t, "keychain-set", "-service", "-w")
	if err == nil || strings.Contains(errOut, "stored") {
		t.Fatalf("keychain-set -service -w: err %v, stderr %q", err, errOut)
	}
}
