package seal

import (
	"bytes"
	"errors"
	"testing"
)

// Open must refuse a nonce of any wrong length with ErrNonce; cipher.AEAD.Open panics on
// one, so a "too short" check alone would let a longer nonce through to the panic.
func TestOpenRefusesEveryWrongNonceLength(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	aad := AAD("keystore/v1", "secret", "k", nil, params())
	_, ct, err := Seal(key, []byte("x"), aad)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, NonceLen - 1, NonceLen + 1, 16, 32} {
		if _, err := Open(key, make([]byte, n), ct, aad); !errors.Is(err, ErrNonce) {
			t.Errorf("Open with a %d-byte nonce = %v, want ErrNonce", n, err)
		}
	}
}

// The cipher is AES-256: a key of any other length, shorter or longer, is refused by both
// directions, not silently run as AES-128/192.
func TestKeyLengthIsExactly32(t *testing.T) {
	aad := AAD("keystore/v1", "secret", "k", nil, params())
	nonce := make([]byte, NonceLen)
	for _, n := range []int{0, 15, 16, 24, 31, 33, 64} {
		key := bytes.Repeat([]byte{1}, n)
		if _, _, err := Seal(key, []byte("x"), aad); err == nil {
			t.Errorf("Seal accepted a %d-byte key", n)
		}
		if _, err := Open(key, nonce, make([]byte, 32), aad); err == nil || errors.Is(err, ErrOpen) {
			t.Errorf("Open with a %d-byte key = %v, want a key-length error (not ErrOpen)", n, err)
		}
	}
}

// Nonce reuse under one key breaks GCM: every Seal must draw a fresh random nonce.
func TestSealNonceIsFreshAndRandom(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	aad := AAD("keystore/v1", "secret", "k", nil, params())
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		nonce, _, err := Seal(key, []byte("x"), aad)
		if err != nil {
			t.Fatal(err)
		}
		if len(nonce) != NonceLen || bytes.Equal(nonce, make([]byte, NonceLen)) {
			t.Fatalf("nonce %x: wrong length or all zero", nonce)
		}
		if seen[string(nonce)] {
			t.Fatalf("nonce %x repeated", nonce)
		}
		seen[string(nonce)] = true
	}
}

// ErrOpen is the only error for an authentication failure, so a wrong passphrase and a
// modified entry cannot be told apart by what comes back.
func TestOpenFailureIsExactlyErrOpen(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	aad := AAD("keystore/v1", "secret", "k", nil, params())
	nonce, ct, _ := Seal(key, []byte("hello"), aad)
	flipped := append([]byte(nil), ct...)
	flipped[0] ^= 1
	if _, err := Open(key, nonce, flipped, aad); err != ErrOpen {
		t.Fatalf("flipped ciphertext: %v, want exactly ErrOpen", err)
	}
	if _, err := Open(key, nonce, ct, append([]byte(nil), aad[1:]...)); err != ErrOpen {
		t.Fatalf("different aad: %v, want exactly ErrOpen", err)
	}
}
