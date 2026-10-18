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
//
// An explicit passfile that a higher source outranks is not ignored invisibly: unlocking
// prints a note, and establishing a passphrase is refused (decision 40).
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

// notice reports that an explicitly given source was passed over; tests replace it.
var notice = func(msg string) { fmt.Fprintln(os.Stderr, msg) }

type sources struct {
	env      string
	keychain bool
	prompt   string
	flag     string // the passfile flag that these sources outrank, for messages
}

var (
	current     = sources{env: EnvVar, keychain: true, prompt: "keystore passphrase: ", flag: "-passfile"}
	established = sources{env: EnvVar, keychain: true, prompt: "new keystore passphrase: ", flag: "-passfile"}
	replacement = sources{env: NewEnvVar, prompt: "new keystore passphrase: ", flag: "-new-passfile"}
)

// Unlock returns the passphrase for an existing ring. No length rule applies.
func Unlock(passfile string) ([]byte, error) {
	pw, _, err := resolve(current, passfile, false)
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
	pw, prompted, err := resolve(src, passfile, true)
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

// shadowed handles an explicit passfile being passed over because a source that outranks
// it is set. The order is documented, but a stale variable silently outranking a flag the
// operator typed hides a misconfiguration (decision 16). When unlocking, that is announced
// and the wrong passphrase will surface at once as a failed unlock. When establishing a
// passphrase it is refused: the ring would be created under a value the operator did not
// mean, silently and persistently.
func shadowed(src sources, passfile, by string, establishing bool) error {
	if passfile == "" {
		return nil
	}
	if establishing {
		return fmt.Errorf("keystore: %s is set and so is %s; unset one so the new passphrase is the one you mean", by, src.flag)
	}
	notice(fmt.Sprintf("keystore: note: %s is set, so %s is ignored", by, src.flag))
	return nil
}

func resolve(src sources, passfile string, establishing bool) (pw []byte, prompted bool, err error) {
	if v, ok := os.LookupEnv(src.env); ok && v != "" {
		if err := shadowed(src, passfile, src.env, establishing); err != nil {
			return nil, false, err
		}
		return []byte(v), false, nil
	}
	if svc := os.Getenv(KeychainVar); src.keychain && svc != "" {
		if err := shadowed(src, passfile, KeychainVar, establishing); err != nil {
			return nil, false, err
		}
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
