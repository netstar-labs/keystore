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
	{"prod cost, password", "password", "somesaltSOMEsalt", 64 * 1024, 3, 1,
		"a50f5d03b1752e16036b1b403db37495fc349636e8c3eed89fb449406dff34f7"},
	{"min mem, min time, min lanes", "password", "somesaltSOMEsalt", 8192, 1, 1,
		"6911fe7649dc2dead68d4216055833f788f2427b52ba7cafb8fb3dbf292d4a38"},
	{"max lanes at min mem", "password", "somesaltSOMEsalt", 8192, 1, 16,
		"f586aaacca394155dd26503ff61023ffe4421ef9296f5bd9ca8f49c8fe93472e"},
	{"max time at min mem", "password", "somesaltSOMEsalt", 8192, 64, 1,
		"7868ac7b3709c7a48e6e40cbae4dbc499bb0b11294851c2be8c6020ac70551ad"},
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
			// And the x/crypto call with its arguments spelled out in the library's order
			// (time, memory, threads), so the two agree about which number is which.
			direct := argon2.IDKey([]byte(v.pass), []byte(v.salt), v.time, v.mem, v.par, 32)
			if !bytes.Equal(got, direct) {
				t.Fatalf("Derive %x != argon2.IDKey %x", got, direct)
			}
		})
	}
}

// initialDefault is kdf.Default as shipped: package variables are initialised before any
// test runs, and some tests in this package lower the global afterwards.
var initialDefault = kdf.Default

// TestKATProductionDefault:kdf.New (what writers use) must derive at exactly 64 MiB,
// 3 passes, 1 lane, which is the cost docs/format.md promises. Checked by deriving with
// the parameters New returns and comparing with the OpenSSL value for the same salt.
func TestKATProductionDefault(t *testing.T) {
	if initialDefault != (kdf.Cost{Mem: 65536, Time: 3, Par: 1}) {
		t.Fatalf("kdf.Default = %+v, docs/format.md says 64 MiB, t=3, p=1", initialDefault)
	}
	// Other tests in this binary lower the global; put the shipped value back for New().
	lowered := kdf.Default
	kdf.Default = initialDefault
	defer func() { kdf.Default = lowered }()
	p, err := kdf.New()
	if err != nil {
		t.Fatal(err)
	}
	if p.Algo != "argon2id" || p.Mem != 65536 || p.Time != 3 || p.Par != 1 || len(p.Salt) != 16 {
		t.Fatalf("New() = %+v", p)
	}
	p.Salt = []byte("somesaltSOMEsalt")
	got, err := p.Derive([]byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "a50f5d03b1752e16036b1b403db37495fc349636e8c3eed89fb449406dff34f7"; hex.EncodeToString(got) != want {
		t.Fatalf("default-cost derivation = %x, want %s", got, want)
	}
}

// TestKATArgumentOrder: time, memory and lanes are all different numbers here, so any
// transposition in Derive changes the key. The expected keys are computed with the
// library's documented order (time, memory, threads) and the transposed calls must differ.
func TestKATArgumentOrder(t *testing.T) {
	pass, salt := []byte("password"), []byte("somesaltSOMEsalt")
	p := kdf.Params{Algo: kdf.Algo, Mem: 16384, Time: 2, Par: 3, Salt: salt}
	got, err := p.Derive(pass)
	if err != nil {
		t.Fatal(err)
	}
	if want := argon2.IDKey(pass, salt, 2, 16384, 3, 32); !bytes.Equal(got, want) {
		t.Fatalf("Derive != IDKey(time=2, mem=16384, par=3): %x vs %x", got, want)
	}
	for name, wrong := range map[string][]byte{
		"time/mem swapped": argon2.IDKey(pass, salt, 16384, 2, 3, 32),
		"time/par swapped": argon2.IDKey(pass, salt, 3, 16384, 2, 32),
		"argon2i":          argon2.Key(pass, salt, 2, 16384, 3, 32),
	} {
		if bytes.Equal(got, wrong) {
			t.Errorf("Derive output equals the %s variant", name)
		}
	}
	// Each parameter and the salt and passphrase move the key (nothing is ignored).
	base := got
	for name, q := range map[string]kdf.Params{
		"mem":  {Algo: kdf.Algo, Mem: 16385, Time: 2, Par: 3, Salt: salt},
		"time": {Algo: kdf.Algo, Mem: 16384, Time: 3, Par: 3, Salt: salt},
		"par":  {Algo: kdf.Algo, Mem: 16384, Time: 2, Par: 4, Salt: salt},
		"salt": {Algo: kdf.Algo, Mem: 16384, Time: 2, Par: 3, Salt: []byte("somesaltSOMEsalu")},
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
