package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// withUmask0 runs the test under umask 0, so a file's mode is exactly the mode asked for.
func withUmask0(t *testing.T) {
	t.Helper()
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })
}

// -force replaces through temp-and-rename and the result has exactly the mode the writer
// asks for (0600 for secrets, 0644 for signatures), whatever the old file's mode was and
// whatever the umask is.
func TestWriteFileModeIsExactAcrossForce(t *testing.T) {
	withUmask0(t)
	dir := t.TempDir()
	for _, c := range []struct {
		name         string
		old, want    os.FileMode
		newPath, ask bool
	}{
		{"secret over a world-readable file", 0o666, 0o600, false, true},
		{"signature over an owner-only file", 0o600, 0o644, false, true},
		{"new secret", 0, 0o600, true, true},
		{"new signature", 0, 0o644, true, true},
	} {
		p := filepath.Join(dir, strings.ReplaceAll(c.name, " ", "-"))
		if !c.newPath {
			if err := os.WriteFile(p, []byte("old"), c.old); err != nil {
				t.Fatal(err)
			}
			os.Chmod(p, c.old)
		}
		if err := writeFile(p, []byte("new"), c.want, true); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		st, _ := os.Stat(p)
		if st.Mode().Perm() != c.want {
			t.Errorf("%s: mode %04o, want %04o", c.name, st.Mode().Perm(), c.want)
		}
		if got, _ := os.ReadFile(p); string(got) != "new" {
			t.Errorf("%s: content %q", c.name, got)
		}
	}
}

// A symlink at the output path is refused with a message that says so, with or without
// -force, and a FIFO or other non-regular file is not replaced even with -force.
func TestWriteFileRefusesSymlinksAndSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("victim"), 0o600)
	link := filepath.Join(dir, "link")
	os.Symlink(target, link)
	for _, force := range []bool{false, true} {
		err := writeFile(link, []byte("x"), 0o600, force)
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Errorf("force=%v: err = %v, want the symlink refusal", force, err)
		}
	}
	if got, _ := os.ReadFile(target); string(got) != "victim" {
		t.Fatal("symlink target modified")
	}

	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	if err := writeFile(fifo, []byte("x"), 0o600, true); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("-force over a FIFO: %v, want the not-a-regular-file refusal", err)
	}
	if st, err := os.Lstat(fifo); err != nil || st.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("the FIFO was replaced: %v, %v", st, err)
	}
}

// A replacement that fails leaves neither the old file damaged nor a temp file behind.
func TestReplaceCleansUpItsTempFileOnFailure(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "occupied")
	if err := os.Mkdir(victim, 0o700); err != nil { // renaming a file over a directory fails
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(victim, "keep"), []byte("x"), 0o600)
	if err := replace(victim, []byte("new"), 0o600); err == nil {
		t.Fatal("replace over a directory succeeded")
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if e.Name() != "occupied" {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// Through the verbs: a signature file is 0644, a private-key file 0600, new or replaced.
func TestSignAndExportOutputModes(t *testing.T) {
	withUmask0(t)
	r, _, msg := signFixture(t)
	dir := t.TempDir()
	sig := filepath.Join(dir, "m.sig")
	if _, _, err := cli(t, "sign", "-keystore", r, "-in", msg, "-o", sig); err != nil {
		t.Fatal(err)
	}
	assertMode(t, sig, 0o644)
	os.Chmod(sig, 0o600)
	if _, _, err := cli(t, "sign", "-keystore", r, "-in", msg, "-o", sig, "-force"); err != nil {
		t.Fatal(err)
	}
	assertMode(t, sig, 0o644)

	key := filepath.Join(dir, "k.pem")
	os.WriteFile(key, []byte("old"), 0o666)
	os.Chmod(key, 0o666)
	if _, _, err := cli(t, "export-priv", "-keystore", r, "-o", key, "-force"); err != nil {
		t.Fatal(err)
	}
	assertMode(t, key, 0o600)
}

// The default ring's directory is created owner-only; a path the operator spells out is
// theirs to prepare, and is not made on their behalf.
func TestDefaultRingDirectoryIsCreatedOwnerOnlyAndOnlyForTheDefault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KEYSTORE_PASSPHRASE", testPass)
	if _, _, err := cli(t, "init"); err != nil {
		t.Fatalf("init at the default location: %v", err)
	}
	dir := filepath.Join(home, ".config", "keystore")
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Errorf("default ring directory mode %04o, want 0700", st.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(dir, "default.ks")); err != nil {
		t.Fatal(err)
	}

	elsewhere := filepath.Join(t.TempDir(), "not", "there", "r.ks")
	for _, verb := range [][]string{{"init"}, {"keygen", "-id", "a"}} {
		if _, _, err := cli(t, append(verb, "-keystore", elsewhere)...); err == nil {
			t.Errorf("%v created a ring in a directory that does not exist", verb)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(elsewhere), "..")); err == nil {
		t.Errorf("a directory was created for an explicit -keystore path")
	}
}

// import needs -key as a usage error (exit 2), not an I/O error about an empty file name.
func TestImportRequiresKeyAsAUsageError(t *testing.T) {
	r := ring(t)
	if _, _, err := cli(t, "import", "-keystore", r, "-id", "a"); !isUsage(err) {
		t.Fatalf("import without -key: %v, want a usage error", err)
	}
	if _, _, err := cli(t, "import", "-keystore", r, "-key", "x.pem"); !isUsage(err) {
		t.Fatalf("import without -id: %v, want a usage error", err)
	}
}

// import-secret's input cap: the largest secret (64 KiB) encoded, with its line ending,
// is accepted from stdin and from a file; a few more bytes are refused as too large rather
// than truncated.
func TestImportSecretInputLimitIsExact(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, 65536))
	if len(enc) != 87384 {
		t.Fatalf("test setup: encoded size %d", len(enc))
	}
	for _, c := range []struct {
		name, input string
		ok          bool
	}{
		{"max secret, LF", enc + "\n", true},
		{"max secret, CRLF (exactly the cap)", enc + "\r\n", true},
		{"max secret, no newline", enc, true},
		{"one byte past the cap", enc + "\r\n\n", false},
		{"far past the cap", enc + strings.Repeat("\n", 100), false},
	} {
		for _, via := range []string{"stdin", "file"} {
			r := ring(t)
			if _, _, err := cli(t, "init", "-keystore", r); err != nil {
				t.Fatal(err)
			}
			args := []string{"import-secret", "-keystore", r, "-id", "s"}
			stdin := ""
			if via == "stdin" {
				stdin = c.input
			} else {
				f := filepath.Join(t.TempDir(), "secret.b64")
				os.WriteFile(f, []byte(c.input), 0o600)
				args = append(args, "-in", f)
			}
			_, _, err := cliIn(t, stdin, args...)
			if c.ok && err != nil {
				t.Errorf("%s via %s: %v", c.name, via, err)
			}
			if !c.ok && (err == nil || !strings.Contains(err.Error(), "too large")) {
				t.Errorf("%s via %s: err = %v, want a too-large refusal", c.name, via, err)
			}
		}
	}
}

// sign and verify take messages up to exactly 1 MiB, from stdin or a file, with or
// without an agent: one byte more is refused, never truncated or signed.
func TestMessageLimitIsExactly1MiB(t *testing.T) {
	r, _, _ := signFixture(t)
	for _, via := range []string{"stdin", "file"} {
		for _, size := range []int{1048576, 1048577} {
			msg := strings.Repeat("m", size)
			args := []string{"sign", "-keystore", r}
			stdin := ""
			if via == "stdin" {
				stdin = msg
			} else {
				f := filepath.Join(t.TempDir(), "msg")
				os.WriteFile(f, []byte(msg), 0o600)
				args = append(args, "-in", f)
			}
			out, _, err := cliIn(t, stdin, args...)
			if size == 1048576 && (err != nil || out == "") {
				t.Errorf("%d bytes via %s: out %q, err %v", size, via, out, err)
			}
			if size == 1048577 && (err == nil || out != "" || !strings.Contains(err.Error(), "digest")) {
				t.Errorf("%d bytes via %s: out %q, err %v; want a refusal and no signature", size, via, out, err)
			}
		}
	}
}

// A signature file that is not a signature at all (wrong length once decoded) is "could
// not check" (exit 1), never "this is bad" (exit 3): automation relies on telling them apart.
func TestMalformedSignatureIsNotABadSignature(t *testing.T) {
	_, pub, msg := signFixture(t)
	dir := t.TempDir()
	for name, content := range map[string]string{
		"base64 of 63 bytes": base64.StdEncoding.EncodeToString(make([]byte, 63)),
		"base64 of 65 bytes": base64.StdEncoding.EncodeToString(make([]byte, 65)),
		"base64 of nothing":  "",
		"65 raw bytes":       strings.Repeat("\x01", 65),
	} {
		f := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		os.WriteFile(f, []byte(content), 0o644)
		_, _, err := cli(t, "verify", "-pub", pub, "-sig", f, "-in", msg)
		if err == nil || errors.Is(err, errBadSig) || !strings.Contains(err.Error(), "neither base64 nor 64 raw bytes") {
			t.Errorf("%s: err = %v, want the malformed-signature error (not errBadSig)", name, err)
		}
	}
	// ...while a well-formed signature by the wrong key is the exit-3 case, and a base64
	// signature wrapped in whitespace is still read.
	_, _, _ = cli(t, "init", "-keystore", filepath.Join(dir, "x.ks"))
	good := base64.StdEncoding.EncodeToString(make([]byte, 64))
	f := filepath.Join(dir, "wrapped")
	os.WriteFile(f, []byte("  \n"+good+"\n\n "), 0o644)
	if _, _, err := cli(t, "verify", "-pub", pub, "-sig", f, "-in", msg); !errors.Is(err, errBadSig) {
		t.Errorf("whitespace-wrapped 64-byte signature: %v, want errBadSig (it parsed, it did not verify)", err)
	}
}
