// Package keychain stores and reads a ring passphrase in the macOS login keychain, as a
// generic password with account "keystore" under a caller-chosen service name.
//
// It drives /usr/bin/security by absolute path. Set lets security prompt for the value
// itself, so the passphrase never appears in any process's arguments. On other
// platforms every call returns ErrUnsupported.
package keychain

import (
	"errors"

	"github.com/netstar-labs/keystore/internal/ids"
)

// Account is the keychain account name under which passphrases are stored.
const Account = "keystore"

var (
	// ErrUnsupported reports a platform without a keychain.
	ErrUnsupported = errors.New("keystore: the keychain passphrase source is macOS-only")
	// ErrNotFound reports that no item exists for the service.
	ErrNotFound = errors.New("keystore: no keychain item for that service")
)

// checkService keeps service names to the entry-id alphabet, so a name can never be
// read by security as an option.
func checkService(service string) error {
	if ids.Valid(service) != nil {
		return errors.New("keystore: keychain service must be 1-64 chars of A-Z a-z 0-9 . _ -, starting alphanumeric")
	}
	return nil
}
