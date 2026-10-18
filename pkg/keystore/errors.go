package keystore

import (
	"errors"

	"github.com/netstar-labs/keystore/internal/ids"
	"github.com/netstar-labs/keystore/internal/ringfile"
	"github.com/netstar-labs/keystore/internal/seal"
)

// Errors returned by this package. Match them with errors.Is.
var (
	// ErrNoKey reports that no entry has the requested id (or the ring has no current key).
	ErrNoKey = errors.New("keystore: no such entry")
	// ErrBadPass reports a wrong passphrase or a modified entry. The two are
	// deliberately indistinguishable.
	ErrBadPass = seal.ErrOpen
	// ErrExists reports that an entry with the id already exists.
	ErrExists = errors.New("keystore: entry id already exists")
	// ErrBadFormat reports a file that is not a valid ring.
	ErrBadFormat = ringfile.ErrBadFormat
	// ErrFutureVersion reports a ring written by a newer format version.
	ErrFutureVersion = ringfile.ErrFutureVersion
	// ErrBadID reports an id outside the permitted alphabet or length.
	ErrBadID = ids.ErrBadID
	// ErrPassphraseMismatch reports a passphrase that does not unlock the ring's
	// existing entries; a ring has exactly one passphrase.
	ErrPassphraseMismatch = errors.New("keystore: passphrase does not match this ring")
	// ErrLocked reports that another process held the ring lock too long.
	ErrLocked = ringfile.ErrLocked
	// ErrNotSigningKey reports an operation that needs a signing key on another kind.
	ErrNotSigningKey = errors.New("keystore: entry is not a signing key")
	// ErrLastSigningKey reports an attempt to remove the only signing key without force.
	ErrLastSigningKey = errors.New("keystore: refusing to remove the last signing key (use force)")
)
