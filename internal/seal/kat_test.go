package seal_test

// Known-answer tests for the seal wiring. The vectors come from outside this repository
// (the GCM specification, OpenSSL) and the AAD bytes are written out by hand from
// docs/format.md, never produced by the code under test, so a change to AES-GCM usage or
// to the associated-data layout fails here even if every round-trip test still passes.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/netstar-labs/keystore/internal/kdf"
	"github.com/netstar-labs/keystore/internal/seal"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// gcmVector is one AES-256-GCM known answer.
type gcmVector struct {
	name                string
	key, nonce, pt, aad string // hex
	ct, tag             string // hex
}

// Sources: McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)", 2005, Appendix B,
// Test Cases 13, 14 and 16 (the 256-bit-key cases with a 96-bit IV; TC15 and 17-18 use a
// 64- or 480-bit IV that Open refuses). The "aad only" rows have no published 256-bit
// counterpart; they were computed with OpenSSL (python3-cryptography on Alpine, 2026-10-19):
//
//	AESGCM(key).encrypt(nonce, b"", aad)
//
// TC13/14/16 were re-run through the same command and reproduced the published values.
var gcmVectors = []gcmVector{
	{
		name:  "TC13 empty plaintext, empty aad",
		key:   "0000000000000000000000000000000000000000000000000000000000000000",
		nonce: "000000000000000000000000",
		ct:    "",
		tag:   "530f8afbc74536b9a963b4f1c4cb738b",
	},
	{
		name:  "TC14 one zero block",
		key:   "0000000000000000000000000000000000000000000000000000000000000000",
		nonce: "000000000000000000000000",
		pt:    "00000000000000000000000000000000",
		ct:    "cea7403d4d606b6e074ec5d3baf39d18",
		tag:   "d0d1c8a799996bf0265b98b5d48ab919",
	},
	{
		name:  "TC16 60-byte plaintext with 20-byte aad",
		key:   "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
		nonce: "cafebabefacedbaddecaf888",
		pt: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" +
			"1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
		ct: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa" +
			"8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
		tag: "76fc6ece0f4e1768cddf8853bb2d551b",
	},
	{
		name:  "aad only (empty plaintext), TC16 key/nonce/aad",
		key:   "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
		nonce: "cafebabefacedbaddecaf888",
		aad:   "feedfacedeadbeeffeedfacedeadbeefabaddad2",
		ct:    "",
		tag:   "9f6be07603c0b0bd1272854063e9c9ba",
	},
	{
		name:  "aad only (empty plaintext), key 00..1f, aad keystore/v1",
		key:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		nonce: "000102030405060708090a0b",
		aad:   "6b657973746f72652f7631",
		ct:    "",
		tag:   "c72b9513ba622f0a50a71a1473580632",
	},
}

func TestKATGCMOpen(t *testing.T) {
	for _, v := range gcmVectors {
		t.Run(v.name, func(t *testing.T) {
			key, nonce, aad := unhex(t, v.key), unhex(t, v.nonce), unhex(t, v.aad)
			ct := unhex(t, v.ct+v.tag)
			pt, err := seal.Open(key, nonce, ct, aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(pt, unhex(t, v.pt)) {
				t.Fatalf("plaintext = %x, want %s", pt, v.pt)
			}
		})
	}
}

// TestKATGCMTamper flips every single bit of every input of every vector. Each must be
// ErrOpen: key, nonce, ciphertext, tag, and aad are all authenticated.
func TestKATGCMTamper(t *testing.T) {
	for _, v := range gcmVectors {
		t.Run(v.name, func(t *testing.T) {
			key, nonce, aad := unhex(t, v.key), unhex(t, v.nonce), unhex(t, v.aad)
			ctBody, tag := unhex(t, v.ct), unhex(t, v.tag)
			ct := append(append([]byte{}, ctBody...), tag...)
			parts := []struct {
				name string
				b    []byte
			}{{"key", key}, {"nonce", nonce}, {"ct", ctBody}, {"tag", tag}, {"aad", aad}}
			for _, p := range parts {
				for i := range p.b {
					for bit := 0; bit < 8; bit++ {
						k, n, c, a := bytes.Clone(key), bytes.Clone(nonce), bytes.Clone(ct), bytes.Clone(aad)
						switch p.name {
						case "key":
							k[i] ^= 1 << bit
						case "nonce":
							n[i] ^= 1 << bit
						case "ct":
							c[i] ^= 1 << bit
						case "tag":
							c[len(ctBody)+i] ^= 1 << bit
						case "aad":
							a[i] ^= 1 << bit
						}
						if _, err := seal.Open(k, n, c, a); !errors.Is(err, seal.ErrOpen) {
							t.Fatalf("flip %s byte %d bit %d: err = %v, want ErrOpen", p.name, i, bit, err)
						}
					}
				}
			}
			// Truncation and extension are tampering too.
			if len(ct) > 0 {
				if _, err := seal.Open(key, nonce, ct[:len(ct)-1], aad); !errors.Is(err, seal.ErrOpen) {
					t.Fatalf("truncated: %v", err)
				}
			}
			if _, err := seal.Open(key, nonce, append(bytes.Clone(ct), 0), aad); !errors.Is(err, seal.ErrOpen) {
				t.Fatalf("extended: %v", err)
			}
			if _, err := seal.Open(key, nonce, ct, append(bytes.Clone(aad), 0)); !errors.Is(err, seal.ErrOpen) {
				t.Fatalf("aad extended: %v", err)
			}
		})
	}
}

// TestKATNonceLength: the format fixes the nonce at 12 bytes. Open refuses every other
// length with ErrNonce, before it touches the key (crypto/cipher would panic).
func TestKATNonceLength(t *testing.T) {
	v := gcmVectors[2]
	key, aad := unhex(t, v.key), unhex(t, v.aad)
	ct := unhex(t, v.ct+v.tag)
	good := unhex(t, v.nonce)
	if len(good) != seal.NonceLen || seal.NonceLen != 12 {
		t.Fatalf("NonceLen = %d, vector nonce %d bytes; want 12", seal.NonceLen, len(good))
	}
	for _, n := range [][]byte{
		nil, {}, good[:1], good[:11], append(bytes.Clone(good), 0), // 13
		append(bytes.Clone(good), 0, 0, 0, 0), // 16, the other length GCM supports natively
		bytes.Repeat([]byte{1}, 64),
	} {
		if _, err := seal.Open(key, n, ct, aad); !errors.Is(err, seal.ErrNonce) {
			t.Errorf("nonce len %d: err = %v, want ErrNonce", len(n), err)
		}
	}
	// ErrNonce comes first even with a bad key, and is not an auth failure.
	if _, err := seal.Open(nil, good[:11], ct, aad); !errors.Is(err, seal.ErrNonce) || errors.Is(err, seal.ErrOpen) {
		t.Errorf("bad nonce + bad key: %v", err)
	}
	// A bad key length is neither.
	if _, err := seal.Open(key[:31], good, ct, aad); err == nil || errors.Is(err, seal.ErrOpen) || errors.Is(err, seal.ErrNonce) {
		t.Errorf("31-byte key: err = %v, want a key-length error", err)
	}
	if _, _, err := seal.Seal(key[:16], []byte("x"), nil); err == nil {
		t.Error("Seal accepted a 16-byte key (AES-128)")
	}
}

// TestKATSealAgainstStdlib: whatever Seal returns must be exactly what AES-256-GCM
// (crypto/aes + crypto/cipher used directly) produces for that key, nonce and aad, and
// must decrypt there; and the reverse. This pins "AES-256, 12-byte nonce, 16-byte tag,
// ciphertext||tag, aad passed as given" independent of the seal package's own newGCM.
func TestKATSealAgainstStdlib(t *testing.T) {
	key := unhex(t, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	aad := unhex(t, "feedfacedeadbeeffeedfacedeadbeefabaddad2")
	for _, pt := range [][]byte{nil, {}, []byte("x"), bytes.Repeat([]byte{0xA5}, 16), bytes.Repeat([]byte{0x5A}, 1000)} {
		nonce, ct, err := seal.Seal(key, pt, aad)
		if err != nil {
			t.Fatal(err)
		}
		if len(nonce) != 12 {
			t.Fatalf("nonce len %d", len(nonce))
		}
		if len(ct) != len(pt)+16 {
			t.Fatalf("ct len %d for pt len %d: want pt+16-byte tag", len(ct), len(pt))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		// Seal's output is exactly stdlib's for the nonce Seal chose.
		if want := gcm.Seal(nil, nonce, pt, aad); !bytes.Equal(ct, want) {
			t.Fatalf("Seal ct = %x, stdlib = %x", ct, want)
		}
		got, err := gcm.Open(nil, nonce, ct, aad)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("stdlib Open of Seal output: %x, %v", got, err)
		}
		// And Open reads what stdlib writes.
		got, err = seal.Open(key, nonce, gcm.Seal(nil, nonce, pt, aad), aad)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("seal.Open of stdlib output: %x, %v", got, err)
		}
		// The aad is bound: Seal output does not open without it.
		if _, err := gcm.Open(nil, nonce, ct, nil); err == nil {
			t.Fatal("ciphertext opened without its aad")
		}
	}
	// Fresh nonce per call.
	n1, _, _ := seal.Seal(key, nil, nil)
	n2, _, _ := seal.Seal(key, nil, nil)
	if bytes.Equal(n1, n2) {
		t.Fatal("two Seals produced the same nonce")
	}
}

// Expected AAD, derived by hand from docs/format.md "Associated data": each field is a
// 4-byte big-endian length then its bytes, in the order
//
//	"keystore/v1" | kind | id | pub | kdf.algo | BE32(mem) | BE32(time) | BE32(par) | salt
//
// with each numeric field itself a length-4 field. Nothing below calls the code under
// test, and the hex is written piece by piece in that order so a reader can check it
// against the doc.
const (
	// "keystore/v1" is 11 bytes (0x0b).
	aadFormat = "0000000b" + "6b657973746f72652f7631"
	// "ed25519" is 7 bytes.
	aadKindEd = "00000007" + "65643235353139"
	// "secret" is 6 bytes.
	aadKindSecret = "00000006" + "736563726574"
	// id "k" is 1 byte.
	aadIDK = "00000001" + "6b"
	// id "s1" is 2 bytes.
	aadIDS1 = "00000002" + "7331"
	// "argon2id" is 8 bytes.
	aadAlgo = "00000008" + "6172676f6e326964"
	// mem 65536 = 0x00010000, time 3, par 1; each a 4-byte field holding a 4-byte value.
	aadMem  = "00000004" + "00010000"
	aadTime = "00000004" + "00000003"
	aadPar  = "00000004" + "00000001"
	// salt: 16 bytes b0..bf.
	aadSalt = "00000010" + "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
	// pub: 32 bytes 01..20 for the signing entry; zero-length for the secret.
	aadPubEd     = "00000020" + "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	aadPubSecret = "00000000"
)

func katParams() kdf.Params {
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = 0xb0 + byte(i)
	}
	return kdf.Params{Algo: "argon2id", Mem: 65536, Time: 3, Par: 1, Salt: salt}
}

func TestKATAADFromDoc(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	cases := []struct {
		name, kind, id string
		pub            []byte
		want           string
	}{
		{"ed25519", "ed25519", "k", pub,
			aadFormat + aadKindEd + aadIDK + aadPubEd + aadAlgo + aadMem + aadTime + aadPar + aadSalt},
		{"secret", "secret", "s1", nil,
			aadFormat + aadKindSecret + aadIDS1 + aadPubSecret + aadAlgo + aadMem + aadTime + aadPar + aadSalt},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := unhex(t, c.want)
			got := seal.AAD("keystore/v1", c.kind, c.id, c.pub, katParams())
			if !bytes.Equal(got, want) {
				t.Fatalf("AAD mismatch\n got  %x\n want %x", got, want)
			}
			// An empty, non-nil pub is the same as an absent one (the doc: "pub is empty for secret entries").
			if c.pub == nil {
				if got := seal.AAD("keystore/v1", c.kind, c.id, []byte{}, katParams()); !bytes.Equal(got, want) {
					t.Fatalf("empty pub differs from nil pub: %x", got)
				}
			}
			// Total length: sum of (4 + len) per field, recomputed from the doc's field list.
			n := 4 + 11 + 4 + len(c.kind) + 4 + len(c.id) + 4 + len(c.pub) + 4 + 8 + 3*(4+4) + 4 + 16
			if len(want) != n {
				t.Fatalf("hand-written AAD is %d bytes, field list says %d", len(want), n)
			}
		})
	}
}

// TestKATAADBindsEntry closes the loop: ciphertext made by stdlib AES-GCM under the
// hand-written AAD opens through seal.Open with seal.AAD's output, and with nothing else.
func TestKATAADBindsEntry(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	key := bytes.Repeat([]byte{0x42}, 32)
	aadDoc := unhex(t, aadFormat+aadKindEd+aadIDK+aadPubEd+aadAlgo+aadMem+aadTime+aadPar+aadSalt)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := bytes.Repeat([]byte{9}, 12)
	ct := gcm.Seal(nil, nonce, []byte("payload"), aadDoc)

	aad := seal.AAD("keystore/v1", "ed25519", "k", pub, katParams())
	if pt, err := seal.Open(key, nonce, ct, aad); err != nil || string(pt) != "payload" {
		t.Fatalf("Open under seal.AAD: %q, %v", pt, err)
	}
	// Every meaning-bearing field, changed alone, must break it.
	mut := func(f func(*kdf.Params)) kdf.Params { p := katParams(); f(&p); return p }
	for name, aad := range map[string][]byte{
		"format": seal.AAD("keystore/v2", "ed25519", "k", pub, katParams()),
		"kind":   seal.AAD("keystore/v1", "secret", "k", pub, katParams()),
		"id":     seal.AAD("keystore/v1", "ed25519", "j", pub, katParams()),
		"pub":    seal.AAD("keystore/v1", "ed25519", "k", pub[:31], katParams()),
		"mem":    seal.AAD("keystore/v1", "ed25519", "k", pub, mut(func(p *kdf.Params) { p.Mem++ })),
		"time":   seal.AAD("keystore/v1", "ed25519", "k", pub, mut(func(p *kdf.Params) { p.Time++ })),
		"par":    seal.AAD("keystore/v1", "ed25519", "k", pub, mut(func(p *kdf.Params) { p.Par++ })),
		"salt":   seal.AAD("keystore/v1", "ed25519", "k", pub, mut(func(p *kdf.Params) { p.Salt[15] ^= 1 })),
		"algo":   seal.AAD("keystore/v1", "ed25519", "k", pub, mut(func(p *kdf.Params) { p.Algo = "argon2i" })),
	} {
		if _, err := seal.Open(key, nonce, ct, aad); !errors.Is(err, seal.ErrOpen) {
			t.Errorf("changing %s: err = %v, want ErrOpen", name, err)
		}
	}
}
