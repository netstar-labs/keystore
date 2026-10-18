package seal

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/netstar-labs/keystore/internal/kdf"
)

func params() kdf.Params {
	return kdf.Params{Algo: kdf.Algo, Mem: 65536, Time: 3, Par: 1, Salt: bytes.Repeat([]byte{7}, kdf.SaltLen)}
}

func TestRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	aad := AAD("keystore/v1", "ed25519", "k", []byte("pub"), params())
	nonce, ct, err := Seal(key, []byte("secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(key, nonce, ct, aad)
	if err != nil || string(pt) != "secret" {
		t.Fatalf("Open = %q, %v", pt, err)
	}
	if _, err := Open(bytes.Repeat([]byte{2}, 32), nonce, ct, aad); !errors.Is(err, ErrOpen) {
		t.Fatalf("wrong key: %v, want ErrOpen", err)
	}
	if _, err := Open(key, nonce[:11], ct, aad); !errors.Is(err, ErrNonce) {
		t.Fatalf("short nonce: %v, want ErrNonce", err)
	}
	if _, err := Open(key, nonce, ct[:3], aad); !errors.Is(err, ErrOpen) {
		t.Fatalf("truncated ct: %v, want ErrOpen", err)
	}
}

// Every field must change the AAD, and moving bytes between adjacent fields must too.
func TestAADBindsEveryField(t *testing.T) {
	base := AAD("keystore/v1", "ed25519", "k", []byte("pub"), params())
	p := params()
	variants := map[string][]byte{
		"format":  AAD("keystore/v2", "ed25519", "k", []byte("pub"), p),
		"kind":    AAD("keystore/v1", "secret", "k", []byte("pub"), p),
		"id":      AAD("keystore/v1", "ed25519", "j", []byte("pub"), p),
		"pub":     AAD("keystore/v1", "ed25519", "k", []byte("puc"), p),
		"shift":   AAD("keystore/v1", "ed25519", "kp", []byte("ub"), p),
		"empty":   AAD("keystore/v1", "ed25519", "k", nil, p),
		"algo":    AAD("keystore/v1", "ed25519", "k", []byte("pub"), with(p, func(q *kdf.Params) { q.Algo = "argon2i" })),
		"mem":     AAD("keystore/v1", "ed25519", "k", []byte("pub"), with(p, func(q *kdf.Params) { q.Mem++ })),
		"time":    AAD("keystore/v1", "ed25519", "k", []byte("pub"), with(p, func(q *kdf.Params) { q.Time++ })),
		"par":     AAD("keystore/v1", "ed25519", "k", []byte("pub"), with(p, func(q *kdf.Params) { q.Par++ })),
		"salt":    AAD("keystore/v1", "ed25519", "k", []byte("pub"), with(p, func(q *kdf.Params) { q.Salt[0]++ })),
		"memtime": AAD("keystore/v1", "ed25519", "k", []byte("pub"), with(p, func(q *kdf.Params) { q.Mem, q.Time = q.Time, q.Mem })),
	}
	seen := map[string]string{string(base): "base"}
	for name, v := range variants {
		if prev, dup := seen[string(v)]; dup {
			t.Errorf("AAD for %s equals AAD for %s", name, prev)
		}
		seen[string(v)] = name
	}
}

func with(p kdf.Params, f func(*kdf.Params)) kdf.Params {
	p.Salt = append([]byte(nil), p.Salt...)
	f(&p)
	return p
}

// Known-answer test for the AAD byte layout. The expected hex was derived independently
// from docs/format.md "Associated data" (a 25-line Python struct.pack script, not this
// package), then compared with AAD's output; it is not produced by the code under test.
// Every ring ever written is only openable if these bytes stay the same.
func TestAADGolden(t *testing.T) {
	spki, _ := hex.DecodeString("302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	salt := func(from byte) []byte {
		b := make([]byte, kdf.SaltLen)
		for i := range b {
			b[i] = from + byte(i)
		}
		return b
	}
	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"ed25519", AAD("keystore/v1", "ed25519", "golden-ed25519", spki,
			kdf.Params{Algo: kdf.Algo, Mem: 65536, Time: 3, Par: 1, Salt: salt(0)}),
			"0000000b6b657973746f72652f763100000007656432353531390000000e676f6c64656e2d656432353531390000002c302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a000000086172676f6e32696400000004000100000000000400000003000000040000000100000010000102030405060708090a0b0c0d0e0f"},
		// pub empty (a secret entry); mem, time and par all different so a swap shows.
		{"secret", AAD("keystore/v1", "secret", "golden-secret", nil,
			kdf.Params{Algo: kdf.Algo, Mem: 8192, Time: 1, Par: 16, Salt: salt(16)}),
			"0000000b6b657973746f72652f7631000000067365637265740000000d676f6c64656e2d73656372657400000000000000086172676f6e32696400000004000020000000000400000001000000040000001000000010101112131415161718191a1b1c1d1e1f"},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(c.got); got != c.want {
			t.Errorf("%s AAD ENCODING CHANGED.\n got  %s\n want %s\nThis breaks every existing ring: each entry's ciphertext is bound to these exact bytes, so "+
				"old entries stop unlocking as \"wrong passphrase or corrupt entry\" (ErrBadPass), indistinguishable from a typo. "+
				"A new layout needs a new format tag (keystore/v2), not a new shape for v1. Do not re-record this golden to make the test pass.", c.name, got, c.want)
		}
	}
}
