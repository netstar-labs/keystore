package keystore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	pemPrivate = "PRIVATE KEY" // PKCS#8, RFC 5958 / RFC 8410
	pemPublic  = "PUBLIC KEY"  // SPKI, RFC 5280 / RFC 8410
)

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

// onePEM returns the bytes of the single PEM block of type typ in b, saying what was found
// when it is something else (an encrypted, PKCS#1 or SEC1 key is the usual surprise).
func onePEM(b []byte, typ string) ([]byte, error) {
	block, rest := pem.Decode(b)
	switch {
	case block == nil:
		return nil, errors.New("keystore: no PEM block found")
	case block.Type != typ:
		hint := ""
		if block.Type == "ENCRYPTED PRIVATE KEY" {
			hint = "; decrypt it first (openssl pkey -in ENCRYPTED.pem -out plain.pem)"
		}
		return nil, fmt.Errorf("keystore: found a %q PEM block, expected %q%s", block.Type, typ, hint)
	case len(block.Headers) != 0:
		return nil, errors.New("keystore: the PEM block has headers (a legacy encrypted key); only a plain PKCS#8 or SPKI block is accepted")
	case len(bytes.TrimSpace(rest)) != 0:
		if next, _ := pem.Decode(rest); next != nil {
			return nil, errors.New("keystore: more than one PEM block; exactly one is expected")
		}
		return nil, errors.New("keystore: unexpected text after the PEM block")
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
