package keystore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"time"

	"github.com/netstar-labs/keystore/internal/ringfile"
)

// Entry kinds.
const (
	KindEd25519 = ringfile.KindEd25519
	KindSecret  = ringfile.KindSecret
)

// Entry is an entry's public metadata. It never carries secret material.
type Entry struct {
	ID          string
	Kind        string
	Current     bool
	Created     time.Time
	Public      ed25519.PublicKey // signing keys only
	Fingerprint string            // signing keys only; see Fingerprint
}

// List returns the metadata of every entry, in ring order.
func (k *Keystore) List() []Entry {
	out := make([]Entry, 0, len(k.f.Entries))
	for _, e := range k.f.Entries {
		le := Entry{ID: e.ID, Kind: e.Kind, Current: e.ID == k.f.Current, Created: e.Created}
		if e.Kind == KindEd25519 {
			le.Public, _ = publicFromSPKI(e.Pub) // validated on parse
			le.Fingerprint = fingerprintSPKI(e.Pub)
		}
		out = append(out, le)
	}
	return out
}

// Public returns the public key of signing key id ("" means current). No passphrase.
func (k *Keystore) Public(id string) (ed25519.PublicKey, error) {
	e, err := k.signingEntry(id)
	if err != nil {
		return nil, err
	}
	return publicFromSPKI(e.Pub)
}

// Fingerprint returns "SHA256:" followed by the unpadded base64 SHA-256 of pub's SPKI
// DER encoding.
func Fingerprint(pub ed25519.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	return fingerprintSPKI(der)
}

func fingerprintSPKI(der []byte) string {
	sum := sha256.Sum256(der)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func publicFromSPKI(der []byte) (ed25519.PublicKey, error) {
	pk, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, ErrBadFormat
	}
	pub, ok := pk.(ed25519.PublicKey)
	if !ok {
		return nil, ErrBadFormat
	}
	return pub, nil
}

func (k *Keystore) signingEntry(id string) (*ringfile.Entry, error) {
	if id == "" {
		id = k.f.Current
		if id == "" {
			return nil, ErrNoKey
		}
	}
	e := k.f.Find(id)
	if e == nil {
		return nil, ErrNoKey
	}
	if e.Kind != KindEd25519 {
		return nil, ErrNotSigningKey
	}
	return e, nil
}
