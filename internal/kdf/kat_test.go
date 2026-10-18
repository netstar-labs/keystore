package kdf_test

// Known-answer tests for the KDF wiring at the production cost and at the bounds. The
// recorded values were produced by OpenSSL 3, a C implementation independent of
// golang.org/x/crypto, so they pin Derive's argument order and parameter units rather
// than echoing the Go code back at itself.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/netstar-labs/keystore/internal/kdf"
	"golang.org/x/crypto/argon2"
)

// Generated 2026-10-19 on Alpine in an Apple `container`, OpenSSL 3.5.9. For each row,
// with PASS, SALT, MEM, TIME and LANES as in the table (threads is not part of the
// result; it is pinned to 1 only because the container has no thread pool):
//
//	openssl kdf -keylen 32 -kdfopt "pass:$PASS" -kdfopt "salt:$SALT" \
//	    -kdfopt "iter:$TIME" -kdfopt "memcost:$MEM" -kdfopt "lanes:$LANES" \
//	    -kdfopt threads:1 ARGON2ID
//
// The first row is the value an earlier run recorded in this repository's kdf_test.go
// (reconstructed from the inputs by search and then reproduced by OpenSSL here).
var kdfVectors = []struct {
	name       string
	pass, salt string
	mem, time  uint32
	par        uint8
	want       string
}{
	{"prod cost, passphrase staple", "correct horse battery staple", "0123456789abcdef", 64 * 1024, 3, 1,
		"94c86f541abdb3d9aabfea59aa03963549483e9c0b1a79336e76b54cee6c917e"},
	{"min mem, min time, min lanes", "password", "somesaltSOMEsalt", 8192, 1, 1,
		"6911fe7649dc2dead68d4216055833f788f2427b52ba7cafb8fb3dbf292d4a38"},
	{"max lanes at min mem", "password", "somesaltSOMEsalt", 8192, 1, 16,
		"f586aaacca394155dd26503ff61023ffe4421ef9296f5bd9ca8f49c8fe93472e"},
	{"two passes at min mem", "password", "somesaltSOMEsalt", 8192, 2, 1,
		"d866e916e3ce07bca9831e9af5aa3c62201c33d67ee2542ff60f71863fc21c55"},
}

func TestKATDeriveVectors(t *testing.T) {
	for _, v := range kdfVectors {
		t.Run(v.name, func(t *testing.T) {
			p := kdf.Params{Algo: kdf.Algo, Mem: v.mem, Time: v.time, Par: v.par, Salt: []byte(v.salt)}
			got, err := p.Derive([]byte(v.pass))
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != v.want {
				t.Fatalf("Derive = %x\n want    %s (OpenSSL 3.5.9)", got, v.want)
			}
		})
	}
}

// TestKATArgumentOrder: time, memory and lanes are all different numbers here, so any
// transposition in Derive changes the key. The expected keys are computed with the
// library's documented order (time, memory, threads); the time/memory transposition is
// pinned by the OpenSSL vectors above (running it here at t=8192 would be slow under -race).
func TestKATArgumentOrder(t *testing.T) {
	pass, salt := []byte("password"), []byte("somesaltSOMEsalt")
	p := kdf.Params{Algo: kdf.Algo, Mem: 8192, Time: 2, Par: 3, Salt: salt}
	got, err := p.Derive(pass)
	if err != nil {
		t.Fatal(err)
	}
	if want := argon2.IDKey(pass, salt, 2, 8192, 3, 32); !bytes.Equal(got, want) {
		t.Fatalf("Derive != IDKey(time=2, mem=8192, par=3): %x vs %x", got, want)
	}
	for name, wrong := range map[string][]byte{
		"time/par swapped": argon2.IDKey(pass, salt, 3, 8192, 2, 32),
		"argon2i":          argon2.Key(pass, salt, 2, 8192, 3, 32),
	} {
		if bytes.Equal(got, wrong) {
			t.Errorf("Derive output equals the %s variant", name)
		}
	}
	// Each parameter and the salt and passphrase move the key (nothing is ignored).
	base := got
	for name, q := range map[string]kdf.Params{
		"mem":  {Algo: kdf.Algo, Mem: 8193, Time: 2, Par: 3, Salt: salt},
		"time": {Algo: kdf.Algo, Mem: 8192, Time: 3, Par: 3, Salt: salt},
		"par":  {Algo: kdf.Algo, Mem: 8192, Time: 2, Par: 4, Salt: salt},
		"salt": {Algo: kdf.Algo, Mem: 8192, Time: 2, Par: 3, Salt: []byte("somesaltSOMEsalu")},
	} {
		k, err := q.Derive(pass)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(k, base) {
			t.Errorf("changing %s did not change the key", name)
		}
	}
	if k, _ := p.Derive([]byte("Password")); bytes.Equal(k, base) {
		t.Error("changing the passphrase did not change the key")
	}
	if len(got) != kdf.KeyLen || kdf.KeyLen != 32 {
		t.Errorf("key length %d, KeyLen %d; want 32", len(got), kdf.KeyLen)
	}
}

// TestKATBoundsTable: docs/format.md gives the accepted ranges; every boundary value is
// accepted and the value one past it refused. The numbers are written out here, not read
// from the kdf constants, so a changed constant is a changed test.
func TestKATBoundsTable(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, 16)
	ok := func() kdf.Params {
		return kdf.Params{Algo: "argon2id", Mem: 65536, Time: 3, Par: 1, Salt: bytes.Clone(salt)}
	}
	if err := ok().Check(); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	type row struct {
		name   string
		mutate func(*kdf.Params)
		accept bool
	}
	rows := []row{
		{"mem 8192 (min)", func(p *kdf.Params) { p.Mem = 8192 }, true},
		{"mem 8191", func(p *kdf.Params) { p.Mem = 8191 }, false},
		{"mem 0", func(p *kdf.Params) { p.Mem = 0 }, false},
		{"mem 1048576 (max)", func(p *kdf.Params) { p.Mem = 1048576 }, true},
		{"mem 1048577", func(p *kdf.Params) { p.Mem = 1048577 }, false},
		{"mem max uint32", func(p *kdf.Params) { p.Mem = 1<<32 - 1 }, false},
		{"time 1 (min)", func(p *kdf.Params) { p.Time = 1 }, true},
		{"time 0", func(p *kdf.Params) { p.Time = 0 }, false},
		{"time 64 (max)", func(p *kdf.Params) { p.Time = 64 }, true},
		{"time 65", func(p *kdf.Params) { p.Time = 65 }, false},
		{"time max uint32", func(p *kdf.Params) { p.Time = 1<<32 - 1 }, false},
		{"par 1 (min)", func(p *kdf.Params) { p.Par = 1 }, true},
		{"par 0", func(p *kdf.Params) { p.Par = 0 }, false},
		{"par 16 (max)", func(p *kdf.Params) { p.Par = 16 }, true},
		{"par 17", func(p *kdf.Params) { p.Par = 17 }, false},
		{"par 255", func(p *kdf.Params) { p.Par = 255 }, false},
		{"salt 16", func(p *kdf.Params) { p.Salt = make([]byte, 16) }, true},
		{"salt 15", func(p *kdf.Params) { p.Salt = make([]byte, 15) }, false},
		{"salt 17", func(p *kdf.Params) { p.Salt = make([]byte, 17) }, false},
		{"salt nil", func(p *kdf.Params) { p.Salt = nil }, false},
		{"algo argon2id", func(p *kdf.Params) { p.Algo = "argon2id" }, true},
		{"algo empty", func(p *kdf.Params) { p.Algo = "" }, false},
		{"algo argon2i", func(p *kdf.Params) { p.Algo = "argon2i" }, false},
		{"algo upper", func(p *kdf.Params) { p.Algo = "ARGON2ID" }, false},
		{"algo trailing space", func(p *kdf.Params) { p.Algo = "argon2id " }, false},
		{"algo scrypt", func(p *kdf.Params) { p.Algo = "scrypt" }, false},
	}
	for _, r := range rows {
		p := ok()
		r.mutate(&p)
		err := p.Check()
		switch {
		case r.accept && err != nil:
			t.Errorf("%s: refused: %v", r.name, err)
		case !r.accept && !errors.Is(err, kdf.ErrParams):
			t.Errorf("%s: err = %v, want ErrParams", r.name, err)
		}
		// Derive checks before doing any work: refusals must be immediate and carry no key.
		if !r.accept {
			if k, err := p.Derive([]byte("x")); k != nil || !errors.Is(err, kdf.ErrParams) {
				t.Errorf("%s: Derive = %x, %v; want nil, ErrParams", r.name, k, err)
			}
		}
	}
	// The exported constants agree with the table (and so with docs/format.md).
	if kdf.MinMem != 8192 || kdf.MaxMem != 1048576 || kdf.MinTime != 1 || kdf.MaxTime != 64 ||
		kdf.MinPar != 1 || kdf.MaxPar != 16 || kdf.SaltLen != 16 || kdf.Algo != "argon2id" {
		t.Error("kdf bound constants differ from docs/format.md")
	}
}
