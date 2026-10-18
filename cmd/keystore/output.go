package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/netstar-labs/keystore/internal/term"
)

// isTerminal is a variable so tests can exercise the terminal guard without a TTY.
var isTerminal = func(f *os.File) bool { return term.IsTerminal(f.Fd()) }

// guardTerminal refuses to send secret material to a terminal on stdout unless forced.
// Callers run it before asking for the passphrase, so a refusal costs nothing.
func guardTerminal(s *stdio, out string, force bool, what string) error {
	if out == "" && !force && s.outFile != nil && isTerminal(s.outFile) {
		return fmt.Errorf("keystore: refusing to write %s to a terminal (use -o FILE, or -force)", what)
	}
	return nil
}

// emit writes secret material to stdout, or to path under writeSecretFile's rules.
func emit(s *stdio, path string, force bool, b []byte, form string) error {
	if path == "" {
		_, err := s.out.Write(b)
		return err
	}
	if err := writeSecretFile(path, b, force); err != nil {
		return err
	}
	fmt.Fprintf(s.err, "wrote %s (%s, 0600)\n", path, form)
	return nil
}

// writeSecretFile writes secret material to path with mode 0600.
//
// A new path is created O_EXCL|O_NOFOLLOW, so it cannot land in a pre-planted file or
// through a symlink. An existing path is refused unless force; with force it is
// replaced by temp-and-rename, so the old file's mode never applies. A symlink at path
// is refused even with force.
func writeSecretFile(path string, b []byte, force bool) error {
	return writeFile(path, b, 0o600, force)
}

// writeFile is writeSecretFile with an explicit mode, for public outputs such as
// signatures.
func writeFile(path string, b []byte, mode os.FileMode, force bool) error {
	st, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return writeNew(path, b, mode)
	case err != nil:
		return err
	case st.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("keystore: %s is a symlink; refusing to write through it", path)
	case !force:
		return fmt.Errorf("keystore: %s exists; refusing to overwrite (use -force)", path)
	case !st.Mode().IsRegular():
		return fmt.Errorf("keystore: %s is not a regular file", path)
	}
	return replace(path, b, mode)
}

func writeNew(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

func replace(path string, b []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
