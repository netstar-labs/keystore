package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/netstar-labs/keystore/internal/keychain"
	"github.com/netstar-labs/keystore/internal/passphrase"
	"github.com/netstar-labs/keystore/internal/term"
	"github.com/netstar-labs/keystore/pkg/keystore"
)

// promptSecret reads a secret without echo; tests replace it.
var promptSecret = term.ReadPassword

func setupAddSecret(fs *flag.FlagSet, s *stdio) func() error {
	ring, pf, id := ringFlag(fs), passfileFlag(fs), idFlag(fs, true)
	return func() error {
		if err := need("id", *id); err != nil {
			return err
		}
		k, err := keystore.Open(*ring)
		if err != nil {
			return err
		}
		pw, err := ringPassphrase(k, *pf)
		if err != nil {
			return err
		}
		defer clear(pw)
		sec, err := k.AddSecret(*id, pw)
		if err != nil {
			return err
		}
		clear(sec)
		fmt.Fprintf(s.err, "added secret %s (%d bytes)\n", *id, keystore.SecretSize)
		return nil
	}
}

func setupImportSecret(fs *flag.FlagSet, s *stdio) func() error {
	ring, pf, id := ringFlag(fs), passfileFlag(fs), idFlag(fs, true)
	in := fs.String("in", "-", "file holding the base64 secret; - for stdin")
	return func() error {
		if err := need("id", *id); err != nil {
			return err
		}
		k, err := keystore.Open(*ring)
		if err != nil {
			return err
		}
		sec, err := readSecret(s, *in)
		if err != nil {
			return err
		}
		defer clear(sec)
		pw, err := ringPassphrase(k, *pf)
		if err != nil {
			return err
		}
		defer clear(pw)
		if err := k.ImportSecret(*id, sec, pw); err != nil {
			return err
		}
		fmt.Fprintf(s.err, "imported secret %s (%d bytes)\n", *id, len(sec))
		return nil
	}
}

// readSecret reads one base64 value: from a file, from piped stdin, or — when stdin is a
// terminal — from a no-echo prompt. Never from argv.
func readSecret(s *stdio, in string) ([]byte, error) {
	limit := int64(base64.StdEncoding.EncodedLen(keystore.MaxSecretSize) + 2)
	var raw []byte
	var err error
	switch {
	case in != "-":
		raw, err = readLimited(in, limit)
	case s.inFile != nil && isTerminal(s.inFile):
		raw, err = promptSecret("secret (base64): ")
	default:
		raw, err = io.ReadAll(io.LimitReader(s.in, limit+1))
		if err == nil && int64(len(raw)) > limit {
			err = errors.New("keystore: secret input too large")
		}
	}
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	trimmed := bytes.TrimSpace(raw)
	sec := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
	n, err := base64.StdEncoding.Decode(sec, trimmed)
	if err != nil {
		clear(sec)
		return nil, errors.New("keystore: secret input is not standard base64")
	}
	return sec[:n], nil
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(b)) > limit {
		clear(b)
		return nil, fmt.Errorf("keystore: %s is too large", path)
	}
	return b, err
}

func setupExportSecret(fs *flag.FlagSet, s *stdio) func() error {
	ring, pf, id := ringFlag(fs), passfileFlag(fs), idFlag(fs, true)
	out := fs.String("o", "", "write to this new file (0600); default stdout")
	force := fs.Bool("force", false, "replace an existing -o file, or allow writing to a terminal")
	return func() error {
		if err := need("id", *id); err != nil {
			return err
		}
		k, err := keystore.Open(*ring)
		if err != nil {
			return err
		}
		if err := guardTerminal(s, *out, *force, "a secret"); err != nil {
			return err
		}
		pw, err := passphrase.Unlock(*pf)
		if err != nil {
			return err
		}
		defer clear(pw)
		sec, err := k.Secret(*id, pw)
		if err != nil {
			return err
		}
		defer clear(sec)
		enc := make([]byte, base64.StdEncoding.EncodedLen(len(sec))+1)
		base64.StdEncoding.Encode(enc, sec)
		enc[len(enc)-1] = '\n'
		defer clear(enc)
		return emit(s, *out, *force, enc, "base64")
	}
}

func setupPasswd(fs *flag.FlagSet, s *stdio) func() error {
	ring, pf := ringFlag(fs), passfileFlag(fs)
	npf := fs.String("new-passfile", "", "read the NEW passphrase from this file (0600, owned by you); env KEYSTORE_NEW_PASSPHRASE")
	return func() error {
		k, err := keystore.Open(*ring)
		if err != nil {
			return err
		}
		oldPw, err := passphrase.Unlock(*pf)
		if err != nil {
			return err
		}
		defer clear(oldPw)
		newPw, err := passphrase.Replacement(*npf)
		if err != nil {
			return err
		}
		defer clear(newPw)
		if bytes.Equal(oldPw, newPw) {
			return errors.New("keystore: the new passphrase is the same as the current one")
		}
		if err := k.ChangePassphrase(oldPw, newPw); err != nil {
			return err
		}
		fmt.Fprintf(s.err, "passphrase changed; %d entries re-encrypted\n", len(k.List()))
		if os.Getenv(passphrase.KeychainVar) != "" {
			fmt.Fprintf(s.err, "note: update the keychain item too: keystore keychain-set -service %s\n", os.Getenv(passphrase.KeychainVar))
		}
		return nil
	}
}

func setupKeychainSet(fs *flag.FlagSet, s *stdio) func() error {
	svc := fs.String("service", "keystore", "keychain service name (use it as KEYSTORE_KEYCHAIN)")
	return func() error {
		if err := keychain.Set(*svc); err != nil {
			return err
		}
		fmt.Fprintf(s.err, "stored; export %s=%s to unlock without a prompt\n", passphrase.KeychainVar, *svc)
		return nil
	}
}
