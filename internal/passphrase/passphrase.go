// Package passphrase resolves where a ring passphrase comes from and enforces the rules
// for establishing a new one. A passphrase is never taken from a command-line flag.
//
// Sources, first match wins:
//
//  1. the KEYSTORE_PASSPHRASE environment variable
//  2. the macOS Keychain, when KEYSTORE_KEYCHAIN names a service; if it is set and the
//     lookup fails, that is an error — an explicitly configured source never silently
//     falls through to the next
//  3. a passfile — owned by the current user, mode 0600 or stricter, not a symlink
//  4. a no-echo prompt on the controlling terminal
//
// A replacement passphrase (for passwd) comes from KEYSTORE_NEW_PASSPHRASE, a new
// passfile, or the prompt — never the keychain or the current-passphrase variable.
package passphrase

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"unicode/utf8"

	"github.com/netstar-labs/keystore/internal/keychain"
	"github.com/netstar-labs/keystore/internal/term"
)

// Environment variables.
const (
	EnvVar      = "KEYSTORE_PASSPHRASE"     // the ring passphrase
	KeychainVar = "KEYSTORE_KEYCHAIN"       // keychain service holding the ring passphrase
	NewEnvVar   = "KEYSTORE_NEW_PASSPHRASE" // a replacement passphrase, for passwd
)

// MinLen is the minimum length of a newly established passphrase, from any source.
const MinLen = 12

const maxFile = 4096

var (
	// ErrEmpty reports an empty passphrase.
	ErrEmpty = errors.New("keystore: empty passphrase")
	// ErrMismatch reports that the confirmation prompt did not match.
	ErrMismatch = errors.New("keystore: passphrases do not match")
	// ErrTooShort reports a new passphrase shorter than MinLen.
	ErrTooShort = fmt.Errorf("keystore: a new passphrase needs at least %d characters", MinLen)
)

// Prompt reads a passphrase interactively; tests replace it.
var Prompt = term.ReadPassword

// Keychain reads a passphrase from the keychain; tests replace it.
var Keychain = keychain.Get

type sources struct {
	env      string
	keychain bool
	prompt   string
}

var (
	current     = sources{env: EnvVar, keychain: true, prompt: "keystore passphrase: "}
	established = sources{env: EnvVar, keychain: true, prompt: "new keystore passphrase: "}
	replacement = sources{env: NewEnvVar, prompt: "new keystore passphrase: "}
)

// Unlock returns the passphrase for an existing ring. No length rule applies.
func Unlock(passfile string) ([]byte, error) {
	pw, _, err := resolve(current, passfile)
	if err != nil {
		return nil, err
	}
	if len(pw) == 0 {
		return nil, ErrEmpty
	}
	return pw, nil
}

// New returns a passphrase being established for a ring. A prompted passphrase is asked
// twice and must match; any source must meet MinLen.
func New(passfile string) ([]byte, error) { return establish(established, passfile) }

// Replacement returns the new passphrase for passwd, under the same rules as New but
// from KEYSTORE_NEW_PASSPHRASE, newPassfile or the prompt.
func Replacement(newPassfile string) ([]byte, error) { return establish(replacement, newPassfile) }

func establish(src sources, passfile string) ([]byte, error) {
	pw, prompted, err := resolve(src, passfile)
	if err != nil {
		return nil, err
	}
	if prompted {
		again, err := Prompt("repeat passphrase: ")
		if err != nil {
			clear(pw)
			return nil, err
		}
		match := bytes.Equal(pw, again)
		clear(again)
		if !match {
			clear(pw)
			return nil, ErrMismatch
		}
	}
	if len(pw) == 0 {
		return nil, ErrEmpty
	}
	// Counted in place: string(pw) would copy the passphrase where clear() cannot reach.
	if utf8.RuneCount(pw) < MinLen {
		clear(pw)
		return nil, ErrTooShort
	}
	return pw, nil
}

func resolve(src sources, passfile string) (pw []byte, prompted bool, err error) {
	if v, ok := os.LookupEnv(src.env); ok && v != "" {
		return []byte(v), false, nil
	}
	if svc := os.Getenv(KeychainVar); src.keychain && svc != "" {
		pw, err := Keychain(svc)
		if err != nil {
			return nil, false, fmt.Errorf("%s=%s: %w", KeychainVar, svc, err)
		}
		return pw, false, nil
	}
	if passfile != "" {
		pw, err := readPassfile(passfile)
		return pw, false, err
	}
	pw, err = Prompt(src.prompt)
	return pw, true, err
}

// readPassfile reads a passfile after checking, on the open descriptor, that it is a
// regular file owned by the caller with no group or other permissions. One trailing
// newline (LF or CRLF) is removed.
func readPassfile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // a FIFO must not block the open
	if err != nil {
		return nil, fmt.Errorf("keystore: passfile: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("keystore: passfile is not a regular file")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("keystore: passfile %s is mode %v; it must be 0600 or stricter", path, st.Mode().Perm())
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Getuid() {
		return nil, fmt.Errorf("keystore: passfile %s is not owned by the current user", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFile {
		return nil, errors.New("keystore: passfile too large")
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	return b, nil
}
