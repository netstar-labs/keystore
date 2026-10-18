package keystore

import (
	"crypto"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
)

// Signer unlocks signing key id ("" means current) with passphrase and returns it as a
// crypto.Signer (an ed25519.PrivateKey). A wrong passphrase or a modified entry is
// ErrBadPass.
func (k *Keystore) Signer(id string, passphrase []byte) (crypto.Signer, error) {
	return k.ExportPrivate(id, passphrase)
}

// ExportPrivate unlocks signing key id ("" means current) and returns the private key,
// for backup or migration. Handle the result with care.
func (k *Keystore) ExportPrivate(id string, passphrase []byte) (ed25519.PrivateKey, error) {
	e, err := k.signingEntry(id)
	if err != nil {
		return nil, err
	}
	pkcs8, err := unlock(e, passphrase)
	if err != nil {
		return nil, err
	}
	defer clear(pkcs8)
	priv, err := parsePKCS8(pkcs8)
	if err != nil {
		return nil, err
	}
	// The AEAD already binds the stored public key to this ciphertext; this is a
	// cheap second check that the key inside is the key advertised.
	spki, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil || subtle.ConstantTimeCompare(spki, e.Pub) != 1 {
		return nil, ErrBadFormat
	}
	return priv, nil
}
