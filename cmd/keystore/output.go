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

// writeSecretFile writes secret material to path with mode 0600.
//
// A new path is created O_EXCL|O_NOFOLLOW, so it cannot land in a pre-planted file or
// through a symlink. An existing path is refused unless force; with force it is
// replaced by temp-and-rename, so the old file's mode never applies. A symlink at path
// is refused even with force.
func writeSecretFile(path string, b []byte, force bool) error {
	st, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return writeNew(path, b)
	case err != nil:
		return err
	case st.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("keystore: %s is a symlink; refusing to write through it", path)
	case !force:
		return fmt.Errorf("keystore: %s exists; refusing to overwrite (use -force)", path)
	case !st.Mode().IsRegular():
		return fmt.Errorf("keystore: %s is not a regular file", path)
	}
	return replace(path, b)
}

func writeNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
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
		return err
	}
	return f.Close()
}

func replace(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if err := f.Chmod(0o600); err != nil {
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
