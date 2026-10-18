// Package keystore is an encrypted, single-file keyring for Ed25519 signing keys and
// opaque secrets.
//
// Each private part is encrypted with AES-256-GCM under a key derived from the ring's
// passphrase by argon2id; public keys and metadata are cleartext, so listing and
// exporting public keys need no passphrase. Every mutation is locked against other
// processes, re-reads the file under the lock, and is written atomically and durably.
//
// A Keystore value is a snapshot: reads (List, Public, Signer) see the ring as of Open
// or this value's last successful mutation. Mutations always act on the file's current
// contents and refresh the snapshot.
package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io/fs"
	"slices"
	"time"

	"github.com/netstar-labs/keystore/internal/ids"
	"github.com/netstar-labs/keystore/internal/kdf"
	"github.com/netstar-labs/keystore/internal/ringfile"
	"github.com/netstar-labs/keystore/internal/seal"
)

// errEmptyPass is the one refusal of an empty passphrase, shared by every path that
// would encrypt under one. Unexported: callers cannot usefully act on it beyond failing.
var errEmptyPass = errors.New("keystore: empty passphrase")

// Keystore is an open ring file.
type Keystore struct {
	path string
	f    *ringfile.File
}

// Create makes a new, empty ring at path with mode 0600. It never replaces an existing
// file; if path exists the error matches fs.ErrExist.
func Create(path string) (*Keystore, error) {
	f := &ringfile.File{}
	if err := ringfile.Create(path, f); err != nil {
		return nil, err
	}
	return &Keystore{path: path, f: f}, nil
}

// Open loads the ring at path.
func Open(path string) (*Keystore, error) {
	f, err := ringfile.Read(path)
	if err != nil {
		return nil, err
	}
	return &Keystore{path: path, f: f}, nil
}

// OpenOrCreate opens the ring at path, creating an empty one if it does not exist.
func OpenOrCreate(path string) (*Keystore, error) {
	k, err := Open(path)
	if !errors.Is(err, fs.ErrNotExist) {
		return k, err
	}
	k, err = Create(path)
	if errors.Is(err, fs.ErrExist) { // lost a creation race: someone else made it
		return Open(path)
	}
	return k, err
}

// Path returns the ring's file path.
func (k *Keystore) Path() string { return k.path }

// CurrentID returns the id of the current (default) signing key, or "".
func (k *Keystore) CurrentID() string { return k.f.Current }

// Add generates a new Ed25519 key under id, encrypts it with passphrase and returns its
// public key. The first signing key in a ring becomes current. If the ring already has
// entries, passphrase must unlock them (ErrPassphraseMismatch otherwise); this is checked
// before the key is generated.
func (k *Keystore) Add(id string, passphrase []byte) (ed25519.PublicKey, error) {
	var pub ed25519.PublicKey
	err := k.addSigning(id, passphrase, func() (ed25519.PrivateKey, error) {
		p, priv, err := ed25519.GenerateKey(rand.Reader)
		pub = p
		return priv, err
	})
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// Import encrypts an existing Ed25519 private key under id. The same passphrase rule as
// Add applies.
func (k *Keystore) Import(id string, priv ed25519.PrivateKey, passphrase []byte) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("keystore: not an ed25519 private key")
	}
	return k.addSigning(id, passphrase, func() (ed25519.PrivateKey, error) { return priv, nil })
}

func (k *Keystore) addSigning(id string, passphrase []byte, key func() (ed25519.PrivateKey, error)) error {
	return k.add(id, ringfile.KindEd25519, passphrase, func() (pub, plaintext []byte, err error) {
		priv, err := key()
		if err != nil {
			return nil, nil, err
		}
		if plaintext, err = x509.MarshalPKCS8PrivateKey(priv); err != nil {
			return nil, nil, err
		}
		if pub, err = x509.MarshalPKIXPublicKey(priv.Public()); err != nil {
			clear(plaintext)
			return nil, nil, err
		}
		return pub, plaintext, nil
	})
}

// add is the one path by which an encrypted entry enters a ring: validate the id, then
// under the lock refuse a duplicate, prove the passphrase against the ring, and only
// then produce the material, encrypt it and append it. An empty passphrase is refused
// first: it would create a ring that opens with no secret at all.
func (k *Keystore) add(id, kind string, passphrase []byte, material func() (pub, plaintext []byte, err error)) error {
	if len(passphrase) == 0 {
		return errEmptyPass
	}
	if err := ids.Valid(id); err != nil {
		return err
	}
	return k.update(func(f *ringfile.File) error {
		if f.Find(id) != nil {
			return ErrExists
		}
		if err := checkPassphrase(f, passphrase); err != nil {
			return err
		}
		pub, plaintext, err := material()
		if err != nil {
			return err
		}
		defer clear(plaintext)
		e, err := encrypt(id, kind, pub, plaintext, passphrase)
		if err != nil {
			return err
		}
		f.Entries = append(f.Entries, e)
		if kind == ringfile.KindEd25519 && f.Current == "" {
			f.Current = id
		}
		return nil
	})
}

// ChangePassphrase re-encrypts every entry under newPass with fresh salts, nonces and the
// current KDF cost, in one atomic write. Every entry is unlocked with oldPass first; if
// any fails, nothing is written and the error is ErrBadPass.
func (k *Keystore) ChangePassphrase(oldPass, newPass []byte) error {
	if len(newPass) == 0 {
		return errEmptyPass
	}
	return k.update(func(f *ringfile.File) error {
		if len(f.Entries) == 0 {
			return errors.New("keystore: ring has no entries; nothing to re-encrypt")
		}
		plain := make([][]byte, len(f.Entries))
		defer func() {
			for _, p := range plain {
				clear(p)
			}
		}()
		for i := range f.Entries {
			p, err := unlock(&f.Entries[i], oldPass)
			if err != nil {
				return err
			}
			plain[i] = p
		}
		for i, e := range f.Entries {
			ne, err := encrypt(e.ID, e.Kind, e.Pub, plain[i], newPass)
			if err != nil {
				return err
			}
			ne.Created = e.Created
			f.Entries[i] = ne
		}
		return nil
	})
}

// Use makes id the current signing key.
func (k *Keystore) Use(id string) error {
	return k.update(func(f *ringfile.File) error {
		e := f.Find(id)
		if e == nil {
			return ErrNoKey
		}
		if e.Kind != ringfile.KindEd25519 {
			return ErrNotSigningKey
		}
		f.Current = id
		return nil
	})
}

// Remove deletes the entry id. Removing the only signing key requires force. If id was
// current, current moves to the first remaining signing key, or to none.
func (k *Keystore) Remove(id string, force bool) error {
	return k.update(func(f *ringfile.File) error {
		i := slices.IndexFunc(f.Entries, func(e ringfile.Entry) bool { return e.ID == id })
		if i < 0 {
			return ErrNoKey
		}
		if f.Entries[i].Kind == ringfile.KindEd25519 && !force && countSigning(f) == 1 {
			return ErrLastSigningKey
		}
		f.Entries = slices.Delete(f.Entries, i, i+1)
		if f.Current == id {
			f.Current = ""
			for _, e := range f.Entries {
				if e.Kind == ringfile.KindEd25519 {
					f.Current = e.ID
					break
				}
			}
		}
		return nil
	})
}

func (k *Keystore) update(fn func(*ringfile.File) error) error {
	f, err := ringfile.Update(k.path, fn)
	if err != nil {
		return err
	}
	k.f = f
	return nil
}

func countSigning(f *ringfile.File) int {
	n := 0
	for _, e := range f.Entries {
		if e.Kind == ringfile.KindEd25519 {
			n++
		}
	}
	return n
}

// checkPassphrase enforces one passphrase per ring: if the ring has any entry, the
// passphrase must unlock the first one.
func checkPassphrase(f *ringfile.File, passphrase []byte) error {
	if len(f.Entries) == 0 {
		return nil
	}
	pt, err := unlock(&f.Entries[0], passphrase)
	if errors.Is(err, seal.ErrOpen) {
		return ErrPassphraseMismatch
	}
	clear(pt)
	return err
}

func encrypt(id, kind string, pub, plaintext, passphrase []byte) (ringfile.Entry, error) {
	p, err := kdf.New()
	if err != nil {
		return ringfile.Entry{}, err
	}
	key, err := p.Derive(passphrase)
	if err != nil {
		return ringfile.Entry{}, err
	}
	defer clear(key)
	nonce, ct, err := seal.Seal(key, plaintext, seal.AAD(ringfile.Magic, kind, id, pub, p))
	if err != nil {
		return ringfile.Entry{}, err
	}
	return ringfile.Entry{ID: id, Kind: kind, Pub: pub, KDF: p, Nonce: nonce, CT: ct,
		Created: time.Now().UTC().Truncate(time.Second)}, nil
}

func unlock(e *ringfile.Entry, passphrase []byte) ([]byte, error) {
	key, err := e.KDF.Derive(passphrase)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return seal.Open(key, e.Nonce, e.CT, seal.AAD(ringfile.Magic, e.Kind, e.ID, e.Pub, e.KDF))
}
