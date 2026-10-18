package passphrase

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// Never consult a developer's real keychain or passphrase from the environment.
	os.Unsetenv(KeychainVar)
	os.Unsetenv(EnvVar)
	os.Unsetenv(NewEnvVar)
	Keychain = func(string) ([]byte, error) { return nil, errors.New("test must not reach the keychain") }
	os.Exit(m.Run())
}

func stubPrompt(t *testing.T, answers ...string) {
	t.Helper()
	old := Prompt
	t.Cleanup(func() { Prompt = old })
	Prompt = func(string) ([]byte, error) {
		if len(answers) == 0 {
			t.Fatal("unexpected prompt")
		}
		a := answers[0]
		answers = answers[1:]
		return []byte(a), nil
	}
}

func passfile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p, mode)
	return p
}

func TestOrderEnvBeatsPassfileBeatsPrompt(t *testing.T) {
	pf := passfile(t, "from the passfile\n", 0o600)
	stubPrompt(t) // any prompt fails the test
	t.Setenv(EnvVar, "from the environment")
	if pw, _ := Unlock(pf); string(pw) != "from the environment" {
		t.Fatalf("env not first: %q", pw)
	}
	t.Setenv(EnvVar, "")
	if pw, _ := Unlock(pf); string(pw) != "from the passfile" {
		t.Fatalf("passfile not second: %q", pw)
	}
}

func TestPromptLast(t *testing.T) {
	t.Setenv(EnvVar, "")
	stubPrompt(t, "typed passphrase")
	if pw, err := Unlock(""); err != nil || string(pw) != "typed passphrase" {
		t.Fatalf("Unlock = %q, %v", pw, err)
	}
}

func TestPassfileRules(t *testing.T) {
	t.Setenv(EnvVar, "")
	if _, err := Unlock(passfile(t, "long enough passphrase", 0o644)); err == nil {
		t.Fatal("0644 passfile accepted")
	}
	if _, err := Unlock(passfile(t, "long enough passphrase", 0o640)); err == nil {
		t.Fatal("0640 passfile accepted")
	}
	if pw, err := Unlock(passfile(t, "crlf passphrase\r\n", 0o400)); err != nil || string(pw) != "crlf passphrase" {
		t.Fatalf("0400 CRLF passfile: %q, %v", pw, err)
	}
	if pw, _ := Unlock(passfile(t, "keeps inner\nlines\n", 0o600)); string(pw) != "keeps inner\nlines" {
		t.Fatalf("only one trailing newline should be trimmed: %q", pw)
	}
	target := passfile(t, "via a symlink", 0o600)
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(target, link)
	if _, err := Unlock(link); err == nil {
		t.Fatal("symlinked passfile accepted")
	}
	if _, err := Unlock(t.TempDir()); err == nil {
		t.Fatal("directory accepted as passfile")
	}
	if _, err := Unlock(passfile(t, "", 0o600)); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty passfile: %v", err)
	}
	if _, err := Unlock(passfile(t, string(make([]byte, maxFile+1)), 0o600)); err == nil {
		t.Fatal("oversize passfile accepted")
	}
}

func TestNewEnforcesLengthFromEverySource(t *testing.T) {
	t.Setenv(EnvVar, "short")
	if _, err := New(""); !errors.Is(err, ErrTooShort) {
		t.Fatalf("short env: %v", err)
	}
	t.Setenv(EnvVar, "")
	if _, err := New(passfile(t, "short\n", 0o600)); !errors.Is(err, ErrTooShort) {
		t.Fatalf("short passfile: %v", err)
	}
	stubPrompt(t, "short", "short")
	if _, err := New(""); !errors.Is(err, ErrTooShort) {
		t.Fatalf("short prompt: %v", err)
	}
	// Unlock never length-checks.
	t.Setenv(EnvVar, "short")
	if _, err := Unlock(""); err != nil {
		t.Fatalf("Unlock length-checked: %v", err)
	}
}

func TestNewPromptConfirms(t *testing.T) {
	t.Setenv(EnvVar, "")
	stubPrompt(t, "twelve chars long", "twelve chars lonG")
	if _, err := New(""); !errors.Is(err, ErrMismatch) {
		t.Fatalf("mismatch: %v", err)
	}
	stubPrompt(t, "twelve chars long", "twelve chars long")
	if pw, err := New(""); err != nil || string(pw) != "twelve chars long" {
		t.Fatalf("match: %q, %v", pw, err)
	}
	// Non-prompt sources are not asked twice.
	t.Setenv(EnvVar, "twelve chars long")
	stubPrompt(t)
	if _, err := New(""); err != nil {
		t.Fatal(err)
	}
}

func stubKeychain(t *testing.T, val string, err error) *[]string {
	t.Helper()
	old := Keychain
	t.Cleanup(func() { Keychain = old })
	var asked []string
	Keychain = func(svc string) ([]byte, error) {
		asked = append(asked, svc)
		return []byte(val), err
	}
	return &asked
}

func TestKeychainOrder(t *testing.T) {
	pf := passfile(t, "from the passfile", 0o600)
	stubPrompt(t)
	asked := stubKeychain(t, "from the keychain", nil)
	t.Setenv(KeychainVar, "svc")

	t.Setenv(EnvVar, "from the environment")
	if pw, _ := Unlock(pf); string(pw) != "from the environment" {
		t.Fatalf("env must beat keychain: %q", pw)
	}
	t.Setenv(EnvVar, "")
	if pw, _ := Unlock(pf); string(pw) != "from the keychain" {
		t.Fatalf("keychain must beat passfile: %q", pw)
	}
	if len(*asked) != 1 || (*asked)[0] != "svc" {
		t.Fatalf("keychain asked for %v", *asked)
	}
	t.Setenv(KeychainVar, "")
	if pw, _ := Unlock(pf); string(pw) != "from the passfile" {
		t.Fatalf("passfile when keychain unset: %q", pw)
	}
}

func TestKeychainFailureDoesNotFallThrough(t *testing.T) {
	pf := passfile(t, "from the passfile", 0o600)
	stubPrompt(t)
	stubKeychain(t, "", errors.New("no item"))
	t.Setenv(EnvVar, "")
	t.Setenv(KeychainVar, "svc")
	if pw, err := Unlock(pf); err == nil {
		t.Fatalf("configured keychain failed but Unlock returned %q", pw)
	}
}

func TestReplacementSources(t *testing.T) {
	stubKeychain(t, "from the keychain", nil)
	t.Setenv(KeychainVar, "svc")
	t.Setenv(EnvVar, "the current passphrase")
	t.Setenv(NewEnvVar, "the replacement passphrase")
	stubPrompt(t)
	if pw, err := Replacement(""); err != nil || string(pw) != "the replacement passphrase" {
		t.Fatalf("Replacement = %q, %v", pw, err)
	}
	// Neither the current-passphrase variable nor the keychain may supply a replacement.
	t.Setenv(NewEnvVar, "")
	stubPrompt(t, "typed replacement!", "typed replacement!")
	if pw, err := Replacement(""); err != nil || string(pw) != "typed replacement!" {
		t.Fatalf("Replacement fell back to %q, %v; want the prompt", pw, err)
	}
	t.Setenv(NewEnvVar, "short")
	if _, err := Replacement(""); !errors.Is(err, ErrTooShort) {
		t.Fatalf("short replacement: %v", err)
	}
	if pw, err := Replacement(passfile(t, "replacement from a file\n", 0o600)); err == nil {
		t.Fatalf("env should win over the new passfile; got %q", pw)
	}
}

// Regression (review): a FIFO at the passfile path blocked the open forever.
func TestPassfileFIFODoesNotBlock(t *testing.T) {
	t.Setenv(EnvVar, "")
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan error, 1)
	go func() { _, err := Unlock(p); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted as a passfile")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("opening a FIFO passfile blocked")
	}
}

// The length check counts runes; converting the passphrase to a string and a []rune for
// that made copies that the surrounding clear() calls can never wipe. It must count in
// place, and count exactly as before (an invalid byte is one rune).
func TestNewLengthCheckMakesNoCopyOfThePassphrase(t *testing.T) {
	long := strings.Repeat("x", 100)
	t.Setenv(EnvVar, long)
	allocs := testing.AllocsPerRun(50, func() {
		pw, err := New("")
		if err != nil {
			t.Fatal(err)
		}
		clear(pw)
	})
	if allocs > 1 { // the one copy is resolve's own []byte(env value), which New returns
		t.Errorf("New allocated %v times for a 100-byte passphrase, want at most 1 (the returned slice)", allocs)
	}
}

func TestNewCountsRunesExactly(t *testing.T) {
	for _, tc := range []struct {
		pw string
		ok bool
	}{
		{strings.Repeat("é", 11), false}, // 22 bytes, 11 runes
		{strings.Repeat("é", 12), true},
		{strings.Repeat("a", 11), false},
		{strings.Repeat("a", 12), true},
		{strings.Repeat("\xff", 11), false}, // an invalid byte counts as one rune
		{strings.Repeat("\xff", 12), true},
		{"日本語のパスフレーズです。。", true}, // 14 runes, 42 bytes
	} {
		t.Setenv(EnvVar, tc.pw)
		pw, err := New("")
		if (err == nil) != tc.ok {
			t.Errorf("New(%q) err = %v, want ok=%v", tc.pw, err, tc.ok)
		}
		clear(pw)
	}
}
