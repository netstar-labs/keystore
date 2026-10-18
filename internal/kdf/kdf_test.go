package kdf

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"golang.org/x/crypto/argon2"
)

// TestDeriveKnownAnswer pins Derive's output. argon2id itself is validated against the
// reference vectors by golang.org/x/crypto's own tests; those vectors use 8-byte salts
// and sub-MiB memory, outside this package's bounds, so they cannot run through Derive.
// What can go wrong here is the wiring — time and memory swapped, lanes dropped — so the
// test (1) checks Derive against a direct argon2.IDKey call with the arguments named, and
// (2) pins a recorded value so any future change to the derivation is caught.
func TestDeriveKnownAnswer(t *testing.T) {
	salt := []byte("0123456789abcdef")
	pass := []byte("correct horse battery staple")
	p := Params{Algo: Algo, Mem: MinMem, Time: 2, Par: 2, Salt: salt}
	got, err := p.Derive(pass)
	if err != nil {
		t.Fatal(err)
	}
	direct := argon2.IDKey(pass, salt, 2 /*time*/, MinMem /*memory KiB*/, 2 /*threads*/, KeyLen)
	if !bytes.Equal(got, direct) {
		t.Fatalf("Derive = %x, argon2.IDKey = %x: parameters wired wrongly", got, direct)
	}
	const recorded = "2dfcfcddbca16abcc42307251ae6cf08073edd9dcdfbdf6ae4a851f419409197"
	if hex.EncodeToString(got) != recorded {
		t.Fatalf("Derive = %x, recorded %s", got, recorded)
	}
}

func TestDeriveDeterministicAndSaltSensitive(t *testing.T) {
	Default = Cost{Mem: MinMem, Time: 1, Par: 1}
	a, _ := New()
	b, _ := New()
	if bytes.Equal(a.Salt, b.Salt) {
		t.Fatal("two New() calls returned the same salt")
	}
	ka1, _ := a.Derive([]byte("pass"))
	ka2, _ := a.Derive([]byte("pass"))
	kb, _ := b.Derive([]byte("pass"))
	if !bytes.Equal(ka1, ka2) || bytes.Equal(ka1, kb) || len(ka1) != KeyLen {
		t.Fatal("derive not deterministic per salt, or not salt-sensitive")
	}
}

func TestCheckBounds(t *testing.T) {
	ok := Params{Algo: Algo, Mem: MinMem, Time: MinTime, Par: MinPar, Salt: make([]byte, SaltLen)}
	if err := ok.Check(); err != nil {
		t.Fatalf("minimums rejected: %v", err)
	}
	hi := Params{Algo: Algo, Mem: MaxMem, Time: MaxTime, Par: MaxPar, Salt: make([]byte, SaltLen)}
	if err := hi.Check(); err != nil {
		t.Fatalf("maximums rejected: %v", err)
	}
	bad := []func(*Params){
		func(p *Params) { p.Algo = "argon2i" },
		func(p *Params) { p.Algo = "" },
		func(p *Params) { p.Mem = MinMem - 1 },
		func(p *Params) { p.Mem = MaxMem + 1 },
		func(p *Params) { p.Mem = 0 },
		func(p *Params) { p.Time = 0 },
		func(p *Params) { p.Time = MaxTime + 1 },
		func(p *Params) { p.Par = 0 },
		func(p *Params) { p.Par = MaxPar + 1 },
		func(p *Params) { p.Salt = make([]byte, SaltLen-1) },
		func(p *Params) { p.Salt = nil },
	}
	for i, mut := range bad {
		p := ok
		p.Salt = append([]byte(nil), ok.Salt...)
		mut(&p)
		if err := p.Check(); !errors.Is(err, ErrParams) {
			t.Errorf("case %d: Check = %v, want ErrParams", i, err)
		}
		if _, err := p.Derive([]byte("x")); !errors.Is(err, ErrParams) {
			t.Errorf("case %d: Derive did not refuse out-of-range params", i)
		}
	}
}
