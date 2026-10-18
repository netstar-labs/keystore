package keystore

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/netstar-labs/keystore/internal/ringfile"
)

// SecretSize is the length of a secret minted by AddSecret.
const SecretSize = 32

// MaxSecretSize bounds an imported secret. Secrets are keys and tokens, not files.
const MaxSecretSize = 64 << 10

// ErrNotSecret reports a secret operation on an entry that is not a secret.
var ErrNotSecret = errors.New("keystore: entry is not a secret")

// AddSecret mints SecretSize random bytes under id, stores them encrypted and returns
// them. The passphrase rule of Add applies. Secrets never become current.
func (k *Keystore) AddSecret(id string, passphrase []byte) ([]byte, error) {
	var out []byte
	err := k.add(id, ringfile.KindSecret, passphrase, func() ([]byte, []byte, error) {
		b := make([]byte, SecretSize)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		out = append([]byte(nil), b...)
		return nil, b, nil
	})
	if err != nil {
		clear(out)
		return nil, err
	}
	return out, nil
}

// ImportSecret stores existing secret bytes (1..MaxSecretSize) encrypted under id.
func (k *Keystore) ImportSecret(id string, secret, passphrase []byte) error {
	if len(secret) == 0 || len(secret) > MaxSecretSize {
		return fmt.Errorf("keystore: a secret must be 1..%d bytes", MaxSecretSize)
	}
	return k.add(id, ringfile.KindSecret, passphrase, func() ([]byte, []byte, error) {
		return nil, append([]byte(nil), secret...), nil
	})
}

// Secret unlocks and returns the secret stored under id. A wrong passphrase or a
// modified entry is ErrBadPass.
func (k *Keystore) Secret(id string, passphrase []byte) ([]byte, error) {
	e := k.f.Find(id)
	if e == nil {
		return nil, ErrNoKey
	}
	if e.Kind != KindSecret {
		return nil, ErrNotSecret
	}
	return unlock(e, passphrase)
}
