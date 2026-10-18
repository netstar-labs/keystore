package keystore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

const (
	pemPrivate = "PRIVATE KEY" // PKCS#8, RFC 5958 / RFC 8410
	pemPublic  = "PUBLIC KEY"  // SPKI, RFC 5280 / RFC 8410
)

var errPEM = errors.New("keystore: expected exactly one PEM block of the right type")

// MarshalPublicKeyPEM encodes pub as an SPKI "PUBLIC KEY" PEM block.
func MarshalPublicKeyPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemPublic, Bytes: der}), nil
}

// MarshalPrivateKeyPEM encodes priv as a PKCS#8 "PRIVATE KEY" PEM block (unencrypted).
func MarshalPrivateKeyPEM(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	return pem.EncodeToMemory(&pem.Block{Type: pemPrivate, Bytes: der}), nil
}

// ParsePublicKeyPEM decodes a single SPKI "PUBLIC KEY" PEM block holding an Ed25519 key.
func ParsePublicKeyPEM(b []byte) (ed25519.PublicKey, error) {
	der, err := onePEM(b, pemPublic)
	if err != nil {
		return nil, err
	}
	return publicFromSPKI(der)
}

// ParsePrivateKeyPEM decodes a single PKCS#8 "PRIVATE KEY" PEM block holding an Ed25519
// key.
func ParsePrivateKeyPEM(b []byte) (ed25519.PrivateKey, error) {
	der, err := onePEM(b, pemPrivate)
	if err != nil {
		return nil, err
	}
	return parsePKCS8(der)
}

func onePEM(b []byte, typ string) ([]byte, error) {
	block, rest := pem.Decode(b)
	if block == nil || block.Type != typ || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errPEM
	}
	return block.Bytes, nil
}

func parsePKCS8(der []byte) (ed25519.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("keystore: not a PKCS#8 private key")
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("keystore: not an ed25519 private key")
	}
	return priv, nil
}
