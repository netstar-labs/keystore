package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

const fuzzPass = "fuzz ring passphrase"

// FuzzRun drives run with fuzzed argv and stdin against a throwaway ring. Invariants: no
// panic; the outcome is the returned error (no os.Exit, no hang on a prompt); nothing
// is written outside the exec's directory; and everything written to stderr, including
// the line report adds for the error, is inert on a terminal.
//
// Containment: every '/' is removed from every argument and the working directory is the
// exec's own, so each path an argument can name is relative to that directory (a bare
// ".." names a directory, which no verb can replace). keychain-set shells out to the
// macOS security tool and is skipped; every other verb finds its passphrase in the
// environment, so none can prompt.
func FuzzRun(f *testing.F) {
	const nul = "\x00"
	seeds := []struct {
		verb  uint8
		argv  string
		stdin string
	}{
		{0, "", ""},                           // init on an existing ring
		{0, "-keystore" + nul + "new.ks", ""}, // init
		{1, "-id" + nul + "k2", ""},           // keygen
		{2, "-id" + nul + "k3", ""},           // add
		{3, "-id" + nul + "imp" + nul + "-in" + nul + "-", "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n-----END PRIVATE KEY-----\n"},
		{4, "", ""},                                 // list
		{5, "-id" + nul + "k", ""},                  // use
		{6, "-id" + nul + "s", ""},                  // rm
		{6, "-id" + nul + "k" + nul + "-force", ""}, // rm -force
		{7, "-id" + nul + "k", ""},                  // export-pub
		{8, "-id" + nul + "k" + nul + "-force", ""}, // export-priv
		{8, "-id" + nul + "k" + nul + "-o" + nul + "priv.pem", ""},
		{9, "-id" + nul + "s2", ""},                                              // add-secret
		{10, "-id" + nul + "s3", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}, // import-secret
		{11, "-id" + nul + "s" + nul + "-force", ""},                             // export-secret
		{12, "", ""},                       // passwd
		{14, "-id" + nul + "k", "message"}, // sign
		{14, "-id" + nul + "k" + nul + "-raw" + nul + "-o" + nul + "sig.bin", "message"},
		{14, "-agent" + nul + "nosuch.sock", "message"},
		{15, "-pub" + nul + "pub.pem" + nul + "-sig" + nul + "sig.b64", "message"},
		{200, "version", ""},
		{200, "-h", ""},
		{200, "list" + nul + "-keystore" + nul + "a\x1b[31mb\rc\u202e", ""},
		{200, "list" + nul + "-\x1b[31mbad\nflag", ""},
		{200, "nosuchverb\x1b]0;x\x07", ""},
		{200, "", ""},
		{4, "-keystore" + nul + "ring.ks.lock", ""},
		{4, "-keystore" + nul + "..", ""},
		{4, "-passfile" + nul + "pass", ""},
	}
	for _, s := range seeds {
		f.Add(s.verb, s.argv, s.stdin)
	}

	// One scratch tree for the whole fuzz run: base/ holds only work/, which is reset
	// and made the working directory on every exec. The ring template is built once.
	base := f.TempDir()
	work := filepath.Join(base, "work")
	wd, err := os.Getwd()
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { os.Chdir(wd) })

	ringPath := filepath.Join(work, "ring.ks")
	setEnv := func(k, v string) {
		old, had := os.LookupEnv(k)
		os.Setenv(k, v)
		f.Cleanup(func() {
			if had {
				os.Setenv(k, old)
			} else {
				os.Unsetenv(k)
			}
		})
	}
	setEnv("KEYSTORE_PASSPHRASE", fuzzPass)
	setEnv("KEYSTORE_NEW_PASSPHRASE", fuzzPass+" (new)")
	setEnv("KEYSTORE_FILE", ringPath)

	reset := func(tb testing.TB) {
		tb.Helper()
		if err := os.RemoveAll(work); err != nil {
			tb.Fatal(err)
		}
		if err := os.Mkdir(work, 0o700); err != nil {
			tb.Fatal(err)
		}
		if err := os.Chdir(work); err != nil {
			tb.Fatal(err)
		}
	}
	reset(f)
	var out, errb bytes.Buffer
	for _, a := range [][]string{
		{"keygen", "-id", "k"},
		{"add-secret", "-id", "s"},
		{"sign", "-id", "k", "-o", "sig.b64", "-force"},
	} {
		if err := run(a, &stdio{in: strings.NewReader("message"), out: &out, err: &errb}); err != nil {
			f.Fatalf("building the template ring: %v: %v", a, err)
		}
	}
	out.Reset()
	if err := run([]string{"export-pub", "-id", "k"}, &stdio{in: strings.NewReader(""), out: &out, err: &errb}); err != nil {
		f.Fatal(err)
	}
	if err := os.WriteFile("pub.pem", out.Bytes(), 0o600); err != nil {
		f.Fatal(err)
	}
	template, err := os.ReadFile(ringPath)
	if err != nil {
		f.Fatal(err)
	}
	pub, _ := os.ReadFile(filepath.Join(work, "pub.pem"))
	sig, _ := os.ReadFile(filepath.Join(work, "sig.b64"))

	f.Fuzz(func(t *testing.T, verb uint8, argv, stdin string) {
		args := strings.Split(argv, "\x00")
		if int(verb) < len(verbs) {
			args = append([]string{verbs[verb].name}, args...)
		}
		if args[0] == "keychain-set" {
			t.Skip("keychain-set execs the macOS security tool")
		}
		for i, a := range args {
			args[i] = strings.ReplaceAll(a, "/", "")
		}

		reset(t)
		if err := os.WriteFile(ringPath, template, 0o600); err != nil {
			t.Fatal(err)
		}
		os.WriteFile("pub.pem", pub, 0o600)
		os.WriteFile("sig.b64", sig, 0o600)
		os.WriteFile("pass", []byte(fuzzPass+"\n"), 0o600)

		var out, errb bytes.Buffer
		err := run(args, &stdio{in: strings.NewReader(stdin), out: &out, err: &errb})
		report(&errb, err)

		if s := errb.String(); !utf8.ValidString(s) {
			t.Fatalf("args %q: stderr is not valid UTF-8: %q", args, s)
		}
		for _, r := range errb.String() {
			if r != '\n' && r != '\t' && !unicode.IsPrint(r) {
				t.Fatalf("args %q: terminal-active rune %U on stderr: %q", args, r, errb.String())
			}
		}
		ents, rerr := os.ReadDir(base)
		if rerr != nil || len(ents) != 1 || ents[0].Name() != "work" {
			t.Fatalf("args %q: wrote outside the working directory: %v %v", args, ents, rerr)
		}
	})
}
