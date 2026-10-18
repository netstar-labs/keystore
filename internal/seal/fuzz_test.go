package seal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/netstar-labs/keystore/internal/kdf"
)

// tuple is everything AAD binds.
type tuple struct {
	format, kind, id string
	pub              []byte
	algo             string
	mem, time        uint32
	par              uint8
	salt             []byte
}

func (t tuple) aad() []byte {
	return AAD(t.format, t.kind, t.id, t.pub, kdf.Params{Algo: t.algo, Mem: t.mem, Time: t.time, Par: t.par, Salt: t.salt})
}

func (t tuple) equal(u tuple) bool {
	return t.format == u.format && t.kind == u.kind && t.id == u.id && bytes.Equal(t.pub, u.pub) &&
		t.algo == u.algo && t.mem == u.mem && t.time == u.time && t.par == u.par && bytes.Equal(t.salt, u.salt)
}

// decodeAAD is the independent inverse of AAD, written from the package doc (length-
// prefixed fields, big-endian uint32) and not from the code. A left inverse exists only
// if AAD is injective, so decoding every encoding back to its tuple proves it for that
// input; it also rejects any prefix, suffix or field-order change.
func decodeAAD(b []byte) (tuple, bool) {
	next := func() ([]byte, bool) {
		if len(b) < 4 {
			return nil, false
		}
		n := binary.BigEndian.Uint32(b)
		if uint64(n) > uint64(len(b)-4) {
			return nil, false
		}
		v := b[4 : 4+n]
		b = b[4+n:]
		return v, true
	}
	num := func() (uint32, bool) {
		v, ok := next()
		if !ok || len(v) != 4 {
			return 0, false
		}
		return binary.BigEndian.Uint32(v), true
	}
	var t tuple
	var ok bool
	var v []byte
	if v, ok = next(); !ok {
		return t, false
	}
	t.format = string(v)
	if v, ok = next(); !ok {
		return t, false
	}
	t.kind = string(v)
	if v, ok = next(); !ok {
		return t, false
	}
	t.id = string(v)
	if v, ok = next(); !ok {
		return t, false
	}
	t.pub = append([]byte{}, v...)
	if v, ok = next(); !ok {
		return t, false
	}
	t.algo = string(v)
	if t.mem, ok = num(); !ok {
		return t, false
	}
	if t.time, ok = num(); !ok {
		return t, false
	}
	p, ok := num()
	if !ok || p > 255 {
		return t, false
	}
	t.par = uint8(p)
	if v, ok = next(); !ok {
		return t, false
	}
	t.salt = append([]byte{}, v...)
	return t, len(b) == 0
}

// shifted returns a tuple that differs from t only in where the boundary between two
// adjacent byte-string fields falls: n bytes move from the end of field i to the start
// of field i+1. The concatenation of those fields is unchanged, so an encoding without
// unambiguous framing would collide.
func shifted(t tuple, i, n uint8) tuple {
	fields := [][]byte{[]byte(t.format), []byte(t.kind), []byte(t.id), t.pub, []byte(t.algo)}
	i %= uint8(len(fields) - 1)
	a, b := fields[i], fields[i+1]
	k := int(n) % (len(a) + 1)
	fields[i], fields[i+1] = a[:len(a)-k], append(append([]byte{}, a[len(a)-k:]...), b...)
	t.format, t.kind, t.id = string(fields[0]), string(fields[1]), string(fields[2])
	t.pub, t.algo = fields[3], string(fields[4])
	return t
}

// FuzzAAD checks, for arbitrary tuples: AAD decodes back to exactly its tuple, and for
// a second tuple (independent, identical, or the same bytes cut at a different
// boundary) the encodings are equal if and only if the tuples are.
func FuzzAAD(f *testing.F) {
	f.Add("keystore/v1", "ed25519", "k", []byte("pub"), "argon2id", uint32(65536), uint32(3), uint8(1), bytes.Repeat([]byte{7}, 16),
		uint8(0), uint8(0), uint8(1), "keystore/v1", "ed25519", "k", []byte("pub"), "argon2id", uint32(65536), uint32(3), uint8(1), bytes.Repeat([]byte{7}, 16))
	f.Add("keystore/v1", "secret", "id", []byte(nil), "argon2id", uint32(8192), uint32(1), uint8(1), bytes.Repeat([]byte{0}, 16),
		uint8(1), uint8(2), uint8(1), "", "", "", []byte(nil), "", uint32(0), uint32(0), uint8(0), []byte(nil))
	// Boundary shifts between id and pub, and kind and id.
	f.Add("keystore/v1", "ed25519", "abc", []byte("def"), "argon2id", uint32(8192), uint32(1), uint8(1), []byte("s"),
		uint8(1), uint8(2), uint8(2), "", "", "", []byte(nil), "", uint32(0), uint32(0), uint8(0), []byte(nil))
	f.Add("", "", "", []byte(nil), "", uint32(0), uint32(0), uint8(0), []byte(nil),
		uint8(1), uint8(0), uint8(0), "", "", "", []byte(nil), "", uint32(0), uint32(0), uint8(0), []byte(nil))
	f.Fuzz(func(t *testing.T,
		format, kind, id string, pub []byte, algo string, mem, tm uint32, par uint8, salt []byte,
		mode, at, n uint8,
		format2, kind2, id2 string, pub2 []byte, algo2 string, mem2, tm2 uint32, par2 uint8, salt2 []byte) {
		a := tuple{format, kind, id, pub, algo, mem, tm, par, salt}
		aad := a.aad()
		if got, ok := decodeAAD(aad); !ok || !got.equal(a) {
			t.Fatalf("AAD does not decode back to its tuple: %+v -> %x -> %+v ok=%v", a, aad, got, ok)
		}
		var b tuple
		switch mode % 3 {
		case 0:
			b = tuple{format2, kind2, id2, pub2, algo2, mem2, tm2, par2, salt2}
		case 1:
			b = a
		default:
			b = shifted(a, at, n)
		}
		bad := b.aad()
		if got, ok := decodeAAD(bad); !ok || !got.equal(b) {
			t.Fatalf("AAD does not decode back to its tuple: %+v -> %x -> %+v ok=%v", b, bad, got, ok)
		}
		if bytes.Equal(aad, bad) != a.equal(b) {
			t.Fatalf("AAD equal=%v but tuples equal=%v:\n%+v\n%+v", bytes.Equal(aad, bad), a.equal(b), a, b)
		}
	})
}

// FuzzSealOpen: Open never panics for any key, nonce, ciphertext and aad lengths; a
// wrong-size nonce or key is refused by name; and what Seal produces opens, and stops
// opening when the aad, ciphertext or nonce changes by one bit.
func FuzzSealOpen(f *testing.F) {
	key := bytes.Repeat([]byte{1}, kdf.KeyLen)
	aad := AAD("keystore/v1", "ed25519", "k", []byte("pub"), params())
	nonce, ct, _ := Seal(key, []byte("secret"), aad)
	f.Add(key, nonce, ct, aad, []byte("secret"))
	f.Add(key[:31], nonce, ct, aad, []byte(nil))
	f.Add(append(key, 0), nonce, ct, aad, []byte(nil))
	f.Add(key, nonce[:11], ct, aad, []byte(nil))
	f.Add(key, append(nonce, 0), ct, aad, []byte(nil))
	f.Add(key, nonce, ct[:15], aad, []byte(nil))
	f.Add(key, nonce, []byte(nil), []byte(nil), []byte(nil))
	f.Add([]byte(nil), []byte(nil), []byte(nil), []byte(nil), []byte(nil))
	f.Fuzz(func(t *testing.T, key, nonce, ct, aad, pt []byte) {
		_, err := Open(key, nonce, ct, aad)
		switch {
		case len(nonce) != NonceLen:
			if !errors.Is(err, ErrNonce) {
				t.Fatalf("nonce of %d bytes: err = %v, want ErrNonce", len(nonce), err)
			}
		case len(key) != kdf.KeyLen:
			if err == nil || errors.Is(err, ErrOpen) {
				t.Fatalf("key of %d bytes: err = %v, want a key-length error", len(key), err)
			}
		case err != nil && !errors.Is(err, ErrOpen): // err == nil: a forged ciphertext, not plausible

			t.Fatalf("Open failed with %v, want ErrOpen", err)
		}

		if len(key) != kdf.KeyLen {
			if _, _, err := Seal(key, pt, aad); err == nil {
				t.Fatalf("Seal accepted a %d-byte key", len(key))
			}
			return
		}
		n, c, err := Seal(key, pt, aad)
		if err != nil {
			t.Fatal(err)
		}
		if len(n) != NonceLen || len(c) != len(pt)+16 {
			t.Fatalf("Seal sizes: nonce %d, ct %d for %d plaintext", len(n), len(c), len(pt))
		}
		if n2, _, err := Seal(key, pt, aad); err != nil || bytes.Equal(n, n2) {
			t.Fatalf("two Seals under one key reused a nonce (err %v)", err)
		}
		back, err := Open(key, n, c, aad)
		if err != nil || !bytes.Equal(back, pt) {
			t.Fatalf("Seal/Open round trip: %v", err)
		}
		flip := func(b []byte) []byte { b = bytes.Clone(b); b[len(b)/2] ^= 1; return b }
		if _, err := Open(key, n, flip(c), aad); !errors.Is(err, ErrOpen) {
			t.Fatalf("flipped ciphertext bit: err = %v", err)
		}
		if _, err := Open(key, flip(n), c, aad); !errors.Is(err, ErrOpen) {
			t.Fatalf("flipped nonce bit: err = %v", err)
		}
		if len(aad) > 0 {
			if _, err := Open(key, n, c, flip(aad)); !errors.Is(err, ErrOpen) {
				t.Fatalf("flipped aad bit: err = %v", err)
			}
		}
		if _, err := Open(key, n, c, append(bytes.Clone(aad), 0)); !errors.Is(err, ErrOpen) {
			t.Fatalf("extended aad: err = %v", err)
		}
	})
}
