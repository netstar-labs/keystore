// Package passphrase resolves where a ring passphrase comes from and enforces the rules
// for establishing a new one. A passphrase is never taken from a command-line flag.
//
// Sources, first match wins:
//
//  1. the KEYSTORE_PASSPHRASE environment variable
//  2. a passfile — owned by the current user, mode 0600 or stricter, not a symlink
//  3. a no-echo prompt on the controlling terminal
//
// The macOS Keychain source arrives in v0.2.0 and slots in between 1 and 2.
package passphrase

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/netstar-labs/keystore/internal/term"
)

// EnvVar names the environment variable source.
const EnvVar = "KEYSTORE_PASSPHRASE"

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

// Unlock returns the passphrase for an existing ring. No length rule applies.
func Unlock(passfile string) ([]byte, error) {
	pw, _, err := resolve(passfile, "keystore passphrase: ")
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
func New(passfile string) ([]byte, error) {
	pw, prompted, err := resolve(passfile, "new keystore passphrase: ")
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
	if len([]rune(string(pw))) < MinLen {
		clear(pw)
		return nil, ErrTooShort
	}
	return pw, nil
}

func resolve(passfile, prompt string) (pw []byte, prompted bool, err error) {
	if v, ok := os.LookupEnv(EnvVar); ok && v != "" {
		return []byte(v), false, nil
	}
	if passfile != "" {
		pw, err := readPassfile(passfile)
		return pw, false, err
	}
	pw, err = Prompt(prompt)
	return pw, true, err
}

// readPassfile reads a passfile after checking, on the open descriptor, that it is a
// regular file owned by the caller with no group or other permissions. One trailing
// newline (LF or CRLF) is removed.
func readPassfile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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
