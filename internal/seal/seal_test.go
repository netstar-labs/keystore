package seal

import (
	"bytes"
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
