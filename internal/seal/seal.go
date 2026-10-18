// Package seal encrypts entry material with AES-256-GCM and builds the associated data
// that binds each ciphertext to the entry's meaning.
//
// Associated data is a sequence of length-prefixed fields (big-endian uint32 length,
// then the bytes), so no field value can be confused with a separator or shifted into
// its neighbour. Every field that changes what an entry means is included: the format
// tag, kind, id, public key, and the KDF parameters and salt. Changing any of them
// makes Open fail.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/netstar-labs/keystore/internal/kdf"
)

// NonceLen is the GCM nonce length.
const NonceLen = 12

// ErrOpen reports an authentication failure: wrong key or modified data. The two are
// deliberately indistinguishable.
var ErrOpen = errors.New("keystore: wrong passphrase or corrupt entry")

// ErrNonce reports a nonce of the wrong length (a format fault, not an auth failure).
var ErrNonce = errors.New("keystore: bad nonce length")

// AAD returns the associated data for one entry.
func AAD(format, kind, id string, pub []byte, p kdf.Params) []byte {
	var b []byte
	field := func(v []byte) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
		b = append(b, v...)
	}
	num := func(n uint32) { field(binary.BigEndian.AppendUint32(nil, n)) }
	field([]byte(format))
	field([]byte(kind))
	field([]byte(id))
	field(pub)
	field([]byte(p.Algo))
	num(p.Mem)
	num(p.Time)
	num(uint32(p.Par))
	field(p.Salt)
	return b
}

// Seal encrypts plaintext under key (32 bytes) with a fresh random nonce.
func Seal(key, plaintext, aad []byte) (nonce, ct []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

// Open decrypts and authenticates ct. Any mismatch in key, nonce, ct or aad is ErrOpen.
func Open(key, nonce, ct, aad []byte) ([]byte, error) {
	if len(nonce) != NonceLen {
		return nil, ErrNonce // gcm.Open panics on a wrong-length nonce
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != kdf.KeyLen {
		return nil, errors.New("keystore: bad key length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
