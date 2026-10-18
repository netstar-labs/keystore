// Package kdf derives entry encryption keys from a passphrase with argon2id, and owns
// the bounds that every stored parameter set must satisfy.
//
// Parameters are stored per entry, so the cost can rise over time without breaking old
// entries. Bounds are checked before any work is done: a crafted ring must not be able
// to force a zero-cost derivation or an out-of-memory allocation.
package kdf

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/argon2"
)

// Algo is the only supported KDF.
const Algo = "argon2id"

// KeyLen is the derived key length: AES-256.
const KeyLen = 32

// SaltLen is the required salt length in bytes.
const SaltLen = 16

// Accepted parameter ranges (inclusive). Mem is in KiB.
const (
	MinMem, MaxMem   = 8 * 1024, 1024 * 1024 // 8 MiB .. 1 GiB
	MinTime, MaxTime = 1, 64
	MinPar, MaxPar   = 1, 16
)

// ErrParams reports a parameter set outside the accepted ranges or an unknown algorithm.
var ErrParams = errors.New("keystore: KDF parameters out of range")

// Params is one entry's KDF parameter set.
type Params struct {
	Algo string
	Mem  uint32 // KiB
	Time uint32 // passes
	Par  uint8  // lanes
	Salt []byte
}

// Cost is the work factor applied to newly written entries.
type Cost struct {
	Mem  uint32
	Time uint32
	Par  uint8
}

// Default is the cost for new entries: 64 MiB, 3 passes, 1 lane. Tests in this module
// may lower it (never below the accepted minimums) to keep suites fast.
var Default = Cost{Mem: 64 * 1024, Time: 3, Par: 1}

// New returns parameters at the Default cost with a fresh random salt.
func New() (Params, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return Params{}, err
	}
	return Params{Algo: Algo, Mem: Default.Mem, Time: Default.Time, Par: Default.Par, Salt: salt}, nil
}

// Check reports whether p is within the accepted ranges.
func (p Params) Check() error {
	if p.Algo != Algo ||
		p.Mem < MinMem || p.Mem > MaxMem ||
		p.Time < MinTime || p.Time > MaxTime ||
		p.Par < MinPar || p.Par > MaxPar ||
		len(p.Salt) != SaltLen {
		return ErrParams
	}
	return nil
}

// Derive returns the KeyLen-byte key for passphrase under p. It checks p first.
func (p Params) Derive(passphrase []byte) ([]byte, error) {
	if err := p.Check(); err != nil {
		return nil, err
	}
	return argon2.IDKey(passphrase, p.Salt, p.Time, p.Mem, p.Par, KeyLen), nil
}
