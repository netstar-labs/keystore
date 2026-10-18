package passphrase

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

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
