package passphrase

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A passfile that is not a regular file is refused for that reason (not merely "it
// failed"): reading a FIFO or device would hand back whatever is on the other end.
func TestPassfileMustBeARegularFile(t *testing.T) {
	t.Setenv(EnvVar, "")
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	if _, err := Unlock(p); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Unlock(FIFO) = %v, want the not-a-regular-file refusal", err)
	}
	dir := t.TempDir()
	if _, err := Unlock(dir); err == nil {
		t.Fatal("a directory was accepted as a passfile")
	}
}

// Every group and other permission bit makes a passfile too open, not just some of them.
func TestPassfileEveryGroupAndOtherBitIsRefused(t *testing.T) {
	t.Setenv(EnvVar, "")
	for _, mode := range []os.FileMode{0o640, 0o620, 0o610, 0o604, 0o602, 0o601, 0o660, 0o606, 0o666, 0o644, 0o700 | 0o001} {
		_, err := Unlock(passfile(t, "long enough passphrase", mode))
		if err == nil || !strings.Contains(err.Error(), "0600 or stricter") {
			t.Errorf("passfile mode %04o: err = %v, want the 0600-or-stricter refusal", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o400, 0o500, 0o700} {
		if pw, err := Unlock(passfile(t, "long enough passphrase", mode)); err != nil || string(pw) != "long enough passphrase" {
			t.Errorf("passfile mode %04o: %q, %v; want it accepted", mode, pw, err)
		}
	}
}

// A passfile owned by someone else is refused. Only root can make one we can still read
// and that is 0600, so this runs only when the suite does (CI containers often do).
func TestPassfileMustBeOwnedByTheCaller(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to create a passfile owned by another user")
	}
	t.Setenv(EnvVar, "")
	p := passfile(t, "long enough passphrase", 0o600)
	if err := os.Chown(p, 12345, 12345); err != nil {
		t.Skip("chown:", err)
	}
	if _, err := Unlock(p); err == nil || !strings.Contains(err.Error(), "not owned by the current user") {
		t.Fatalf("Unlock(foreign-owned passfile) = %v, want the ownership refusal", err)
	}
}

// The size cap is 4096 bytes: that exact file is read, one byte more is refused rather
// than silently truncated into a different passphrase.
func TestPassfileSizeCapIsExactly4096(t *testing.T) {
	t.Setenv(EnvVar, "")
	at := strings.Repeat("p", 4096)
	if pw, err := Unlock(passfile(t, at, 0o600)); err != nil || string(pw) != at {
		t.Fatalf("4096-byte passfile: %d bytes, %v", len(pw), err)
	}
	if pw, err := Unlock(passfile(t, at+"p", 0o600)); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("4097-byte passfile: %d bytes, %v; want the too-large refusal", len(pw), err)
	}
	if _, err := Unlock(passfile(t, strings.Repeat("p", 10000), 0o600)); err == nil {
		t.Fatal("10000-byte passfile accepted")
	}
}

// Exactly one trailing line ending is the file's, everything else is the passphrase:
// trailing spaces and further blank lines are significant.
func TestPassfileTrimsOnlyOneLineEnding(t *testing.T) {
	t.Setenv(EnvVar, "")
	for in, want := range map[string]string{
		"pass word \n":       "pass word ",
		" lead and trail \n": " lead and trail ",
		"tabs\t\n":           "tabs\t",
		"two\n\n":            "two\n",
		"crlf\r\n":           "crlf",
		"no newline":         "no newline",
		"inner\r\nline\r\n":  "inner\r\nline",
		"trailing space ":    "trailing space ",
	} {
		pw, err := Unlock(passfile(t, in, 0o600))
		if err != nil || string(pw) != want {
			t.Errorf("passfile %q: got %q, %v; want %q", in, pw, err, want)
		}
	}
	// Only line endings: nothing left, so an empty passphrase.
	if _, err := Unlock(passfile(t, "\n", 0o600)); !errors.Is(err, ErrEmpty) {
		t.Errorf("passfile of one newline: %v, want ErrEmpty", err)
	}
}

// A keychain that was asked for and failed is an error that says so and carries the
// cause; the caller must not be left with an empty passphrase and a generic message.
func TestKeychainFailureNamesTheServiceAndWrapsTheCause(t *testing.T) {
	cause := errors.New("item not found in login keychain")
	stubKeychain(t, "", cause)
	stubPrompt(t)
	t.Setenv(EnvVar, "")
	t.Setenv(KeychainVar, "my-service")
	_, err := Unlock("")
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), KeychainVar) || !strings.Contains(err.Error(), "my-service") {
		t.Fatalf("Unlock = %v, want an error naming %s=my-service and wrapping the keychain's", err, KeychainVar)
	}
}

// Passphrases that were typed are wiped from memory on every path that does not return
// them: the Prompt stub keeps the slices it hands out so the wipe can be observed.
func TestEstablishWipesWhatItDoesNotReturn(t *testing.T) {
	t.Setenv(EnvVar, "")
	t.Setenv(NewEnvVar, "")
	zeroed := func(b []byte) bool { return bytes.Equal(b, make([]byte, len(b))) }
	script := func(t *testing.T, replies ...[]byte) {
		t.Helper()
		old := Prompt
		t.Cleanup(func() { Prompt = old })
		i := 0
		Prompt = func(string) ([]byte, error) {
			if i >= len(replies) {
				return nil, errors.New("prompt: no more replies")
			}
			r := replies[i]
			i++
			if r == nil {
				return nil, errors.New("terminal went away")
			}
			return r, nil
		}
	}

	t.Run("confirmation mismatch", func(t *testing.T) {
		a, b := []byte("a long enough one"), []byte("another long enough")
		script(t, a, b)
		if _, err := New(""); !errors.Is(err, ErrMismatch) {
			t.Fatalf("New = %v, want ErrMismatch", err)
		}
		if !zeroed(a) || !zeroed(b) {
			t.Errorf("not wiped after a mismatch: first %q, repeat %q", a, b)
		}
	})
	t.Run("confirmation prompt fails", func(t *testing.T) {
		a := []byte("a long enough one")
		script(t, a, nil)
		if _, err := New(""); err == nil {
			t.Fatal("New succeeded though the confirmation prompt failed")
		}
		if !zeroed(a) {
			t.Errorf("first entry not wiped when the repeat failed: %q", a)
		}
	})
	t.Run("too short", func(t *testing.T) {
		a, b := []byte("short"), []byte("short")
		script(t, a, b)
		if _, err := New(""); !errors.Is(err, ErrTooShort) {
			t.Fatalf("New = %v, want ErrTooShort", err)
		}
		if !zeroed(a) || !zeroed(b) {
			t.Errorf("not wiped after a too-short passphrase: %q / %q", a, b)
		}
	})
	t.Run("success wipes only the repeat", func(t *testing.T) {
		a, b := []byte("a long enough one"), []byte("a long enough one")
		script(t, a, b)
		pw, err := New("")
		if err != nil || string(pw) != "a long enough one" {
			t.Fatalf("New = %q, %v", pw, err)
		}
		if !zeroed(b) {
			t.Errorf("the confirmation copy was not wiped: %q", b)
		}
	})
}

// Establishing a passphrase from an empty source is ErrEmpty, not the length error: the
// operator's mistake is "I gave nothing", and a script can tell the two apart.
func TestEstablishFromNothingIsErrEmpty(t *testing.T) {
	t.Setenv(EnvVar, "")
	t.Setenv(NewEnvVar, "")
	empty := passfile(t, "\n", 0o600)
	if _, err := New(empty); !errors.Is(err, ErrEmpty) {
		t.Errorf("New(empty passfile) = %v, want ErrEmpty", err)
	}
	if _, err := Replacement(empty); !errors.Is(err, ErrEmpty) {
		t.Errorf("Replacement(empty passfile) = %v, want ErrEmpty", err)
	}
	stubPrompt(t, "", "")
	if _, err := New(""); !errors.Is(err, ErrEmpty) {
		t.Errorf("New(prompt answered with nothing) = %v, want ErrEmpty", err)
	}
	if _, err := Unlock(empty); !errors.Is(err, ErrEmpty) {
		t.Errorf("Unlock(empty passfile) = %v, want ErrEmpty", err)
	}
}

// An empty environment variable is "unset", so lower sources still apply; a non-empty
// one wins over an explicit passfile and the notice says so (documented order).
func TestEmptyEnvFallsThroughAndPassfileNeverOutranksTheEnv(t *testing.T) {
	pf := passfile(t, "from the passfile", 0o600)
	notes := captureNotices(t)
	stubPrompt(t)
	t.Setenv(EnvVar, "")
	if pw, err := Unlock(pf); err != nil || string(pw) != "from the passfile" {
		t.Fatalf("empty env var did not fall through: %q, %v", pw, err)
	}
	if len(*notes) != 0 {
		t.Fatalf("a note was printed though nothing was shadowed: %v", *notes)
	}
	t.Setenv(EnvVar, "from the env")
	if pw, err := Unlock(pf); err != nil || string(pw) != "from the env" {
		t.Fatalf("env var did not win: %q, %v", pw, err)
	}
	if len(*notes) != 1 || !strings.Contains((*notes)[0], EnvVar) {
		t.Fatalf("shadowing was not announced: %v", *notes)
	}
}

// The keychain outranks a passfile too, and the replacement never reads it.
func TestKeychainOutranksPassfileButNotForReplacement(t *testing.T) {
	pf := passfile(t, "from the passfile!", 0o600)
	stubKeychain(t, "from the keychain!", nil)
	stubPrompt(t)
	captureNotices(t)
	t.Setenv(EnvVar, "")
	t.Setenv(NewEnvVar, "")
	t.Setenv(KeychainVar, "svc")
	if pw, err := Unlock(pf); err != nil || string(pw) != "from the keychain!" {
		t.Fatalf("Unlock = %q, %v; want the keychain's", pw, err)
	}
	if pw, err := Replacement(pf); err != nil || string(pw) != "from the passfile!" {
		t.Fatalf("Replacement = %q, %v; want the passfile (never the keychain)", pw, err)
	}
}
