package keystore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/netstar-labs/keystore/internal/kdf"
	"github.com/netstar-labs/keystore/internal/ringfile"
)

// Fuzz targets for the two byte-parsing surfaces of this package: the ring file as
// reached through Open, and the PEM key parsers. Seeds live in the tests (f.Add) because
// package testdata/ directories are not committed.

// ringSeeds returns real rings: the committed golden ring and rings this package writes.
func ringSeeds(tb testing.TB) [][]byte {
	tb.Helper()
	seeds := [][]byte{mustRead(tb, goldenPath)}
	k, err := Create(filepath.Join(tb.TempDir(), "r.ks"))
	if err != nil {
		tb.Fatal(err)
	}
	seeds = append(seeds, mustRead(tb, k.Path())) // empty ring
	if _, err := k.Add("sign", pass); err != nil {
		tb.Fatal(err)
	}
	if _, err := k.AddSecret("sec", pass); err != nil {
		tb.Fatal(err)
	}
	return append(seeds, mustRead(tb, k.Path()))
}

var idRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

var createdRe = regexp.MustCompile(`"created": "[^"]*"`)

func mustRead(tb testing.TB, path string) []byte {
	tb.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// FuzzOpenRing feeds arbitrary bytes to the ring parser through Open on a real file.
// Invariants: no panic; a ring Open accepts re-marshals and re-parses to an equal File;
// List, Public and Signer never panic on it; and Open allocates in proportion to the
// input (the guard for the Parse amplification fix, audit W2-4-1: decoding the entries
// array whole cost ~100x the input before anything was validated).
func FuzzOpenRing(f *testing.F) {
	for _, s := range ringSeeds(f) {
		f.Add(s)
	}
	// Semantic edits of a real ring that a byte-flipping engine rarely reaches: a created
	// time with a zone offset (must normalise to UTC), and a current pointer that is
	// dangling or names a secret.
	good := ringSeeds(f)[2]
	f.Add(createdRe.ReplaceAll(good, []byte(`"created": "2026-10-18T12:00:00+05:30"`)))
	f.Add(bytes.Replace(good, []byte(`"current": "sign"`), []byte(`"current": "nosuch"`), 1))
	f.Add(bytes.Replace(good, []byte(`"current": "sign"`), []byte(`"current": "sec"`), 1))
	// Entry-level violations the parser must refuse (the acceptance oracle below checks
	// that nothing violating them gets through), and two boundary-valid neighbours.
	second := func(es []any) map[string]any { return es[1].(map[string]any) }
	for _, edit := range []func(top map[string]any, es []any){
		func(top map[string]any, es []any) { top["entries"] = append(es, es[0]) },                // duplicate id
		func(top map[string]any, es []any) { second(es)["pub"] = es[0].(map[string]any)["pub"] }, // secret with pub
		func(top map[string]any, es []any) { second(es)["kind"] = "other" },                      // unknown kind
		func(top map[string]any, es []any) { second(es)["ct"] = "AAAAAAAAAAAAAAAAAAAA" },         // 15-byte ct
		func(top map[string]any, es []any) { second(es)["ct"] = "AAAAAAAAAAAAAAAAAAAAAA==" },     // 16-byte ct: valid
		func(top map[string]any, es []any) { second(es)["nonce"] = "AAAAAAAAAAA=" },              // 8-byte nonce
		func(top map[string]any, es []any) { second(es)["nonce"] = "AAAAAAAAAAAAAAAA" },          // 12-byte nonce: valid
		func(top map[string]any, es []any) { second(es)["id"] = "sign" },                         // duplicate id, second entry
		func(top map[string]any, es []any) { second(es)["id"] = "-lead" },                        // bad id
	} {
		var top map[string]any
		if err := json.Unmarshal(good, &top); err != nil {
			f.Fatal(err)
		}
		edit(top, top["entries"].([]any))
		b, _ := json.MarshalIndent(top, "", "  ")
		f.Add(b)
	}
	f.Add([]byte(`{"magic":"keystore/v1","current":"","entries":[]}`))
	f.Add([]byte(`{"magic":"keystore/v1","entries":null}`))
	f.Add([]byte(`{"magic":"keystore/v9"}`))
	// Amplification seeds: tens of thousands of tiny entries. A decoder that builds the
	// whole []wireEntry first spends >100 bytes per 3 input bytes.
	f.Add([]byte(`{"magic":"keystore/v1","entries":[` + strings.Repeat(`{},`, 40_000) + `{}]}`))
	f.Add([]byte(`{"magic":"keystore/v1","entries":[` + strings.Repeat(`[],`, 40_000) + `[]]}`))
	f.Add([]byte(`{"magic":"keystore/v1","entries":[` + strings.Repeat(`{"kdf":{"salt":null}},`, 5_000) + `{}]}`))

	path := filepath.Join(f.TempDir(), "fuzz.ks")
	f.Fuzz(func(t *testing.T, b []byte) {
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		k, err := Open(path)
		runtime.ReadMemStats(&after)
		// Generous: reading the file costs a few copies, parsing a few more.
		if grew, limit := after.TotalAlloc-before.TotalAlloc, uint64(len(b))*64+8<<20; grew > limit {
			t.Fatalf("Open of %d bytes allocated %d bytes (limit %d)", len(b), grew, limit)
		}
		if err != nil {
			return
		}

		// Round trip: what Open accepted must encode and decode to the same ring.
		out, err := ringfile.Marshal(k.f)
		if err != nil {
			t.Fatalf("accepted ring does not re-marshal: %v", err)
		}
		again, err := ringfile.Parse(out)
		if err != nil {
			t.Fatalf("re-marshalled ring does not parse: %v", err)
		}
		if !reflect.DeepEqual(k.f, again) {
			t.Fatalf("Parse(Marshal(f)) != f:\n%+v\n%+v", k.f, again)
		}
		if out2, _ := ringfile.Marshal(again); !bytes.Equal(out, out2) {
			t.Fatal("Marshal is not stable across a round trip")
		}

		if cur := k.CurrentID(); cur != "" {
			if e := k.f.Find(cur); e == nil || e.Kind != KindEd25519 {
				t.Fatalf("accepted a current pointer %q that names no signing key", cur)
			}
		}

		// Independent acceptance oracle: whatever Open let through must satisfy the format
		// rules, stated here without the parser's helpers.
		seen := map[string]bool{}
		for i, e := range k.f.Entries {
			switch {
			case !idRe.MatchString(e.ID):
				t.Fatalf("entry %d: accepted id %q", i, e.ID)
			case seen[e.ID]:
				t.Fatalf("entry %d: accepted duplicate id %q", i, e.ID)
			case len(e.Nonce) != 12:
				t.Fatalf("entry %d: accepted a %d-byte nonce", i, len(e.Nonce))
			case len(e.CT) < 16:
				t.Fatalf("entry %d: accepted a %d-byte ciphertext", i, len(e.CT))
			case e.Kind != "ed25519" && e.Kind != "secret":
				t.Fatalf("entry %d: accepted kind %q", i, e.Kind)
			case e.Kind == "secret" && len(e.Pub) != 0:
				t.Fatalf("entry %d: accepted a secret entry carrying a public key", i)
			case e.Kind == "ed25519" && len(e.Pub) == 0:
				t.Fatalf("entry %d: accepted a signing entry with no public key", i)
			}
			seen[e.ID] = true
		}

		// Nothing a parsed ring holds may make the read paths panic.
		entries := k.List()
		if len(entries) != len(k.f.Entries) {
			t.Fatalf("List returned %d entries for %d", len(entries), len(k.f.Entries))
		}
		for i, e := range entries {
			if e.Kind != KindEd25519 {
				continue
			}
			pub, err := k.Public(e.ID)
			if err != nil || len(pub) != ed25519.PublicKeySize || !bytes.Equal(pub, e.Public) {
				t.Fatalf("Public(%q) = %x, %v; List says %x", e.ID, pub, err, e.Public)
			}
			// Signer derives a key; only attempt it where the stored cost is small, so a
			// crafted 1 GiB parameter set cannot turn the fuzz run into a memory test.
			if c := k.f.Entries[i].KDF; c.Mem <= 2*kdf.MinMem && c.Time <= 2 && c.Par <= 2 {
				k.Signer(e.ID, pass) // an error is the expected outcome; a panic is the bug
			}
		}
		if _, err := k.Public(""); err != nil && k.CurrentID() != "" {
			t.Fatalf("current %q is set but Public(\"\") = %v", k.CurrentID(), err)
		}
	})
}

// FuzzParsePEM covers ParsePrivateKeyPEM and ParsePublicKeyPEM: no panic, accepted input
// re-encodes to something that parses to the same key, and accept/reject agrees with a
// reference built straight on encoding/pem and crypto/x509.
func FuzzParsePEM(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	privPEM, _ := MarshalPrivateKeyPEM(priv)
	pubPEM, _ := MarshalPublicKeyPEM(pub)
	for _, s := range [][]byte{
		privPEM, pubPEM,
		append(append([]byte{}, privPEM...), privPEM...), // two blocks
		append(append([]byte{}, privPEM...), "trailing\n"...),
		append([]byte("junk before\n"), privPEM...),
		bytes.ReplaceAll(privPEM, []byte("PRIVATE KEY"), []byte("ENCRYPTED PRIVATE KEY")),
		bytes.ReplaceAll(privPEM, []byte("PRIVATE KEY"), []byte("RSA PRIVATE KEY")),
		bytes.ReplaceAll(privPEM, []byte("-----BEGIN PRIVATE KEY-----\n"), []byte("-----BEGIN PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n")),
		bytes.ReplaceAll(privPEM, []byte("\n"), []byte("\r\n")),
		append(append([]byte{}, pubPEM...), " \t\r\n\n"...),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY"}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv.Seed()}),
		{},
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		gotPriv, errPriv := ParsePrivateKeyPEM(b)
		wantPriv, rejected := refPrivate(b)
		if (errPriv == nil) == rejected || (errPriv == nil && !bytes.Equal(gotPriv, wantPriv)) {
			t.Fatalf("ParsePrivateKeyPEM: err=%v; reference rejected=%v", errPriv, rejected)
		}
		if errPriv == nil {
			enc, err := MarshalPrivateKeyPEM(gotPriv)
			if err != nil {
				t.Fatal(err)
			}
			back, err := ParsePrivateKeyPEM(enc)
			if err != nil || !back.Equal(gotPriv) {
				t.Fatalf("private key does not round-trip: %v", err)
			}
			if enc2, _ := MarshalPrivateKeyPEM(back); !bytes.Equal(enc, enc2) {
				t.Fatal("private PEM encoding is not stable")
			}
		}

		gotPub, errPub := ParsePublicKeyPEM(b)
		wantPub, rejected := refPublic(b)
		if (errPub == nil) == rejected || (errPub == nil && !bytes.Equal(gotPub, wantPub)) {
			t.Fatalf("ParsePublicKeyPEM: err=%v; reference rejected=%v", errPub, rejected)
		}
		if errPub == nil {
			enc, err := MarshalPublicKeyPEM(gotPub)
			if err != nil {
				t.Fatal(err)
			}
			back, err := ParsePublicKeyPEM(enc)
			if err != nil || !back.Equal(gotPub) {
				t.Fatalf("public key does not round-trip: %v", err)
			}
		}
		if errPriv == nil && errPub == nil {
			t.Fatal("one input parsed as both a private and a public key")
		}
	})
}

// refBlock is the reference for "exactly one plain PEM block of this type", stated
// directly from encoding/pem rather than through onePEM. It returns the DER and whether
// the input was rejected.
func refBlock(b []byte, typ string) ([]byte, bool) {
	block, rest := pem.Decode(b)
	if block == nil || block.Type != typ || len(block.Headers) != 0 {
		return nil, true
	}
	if len(bytes.TrimSpace(rest)) != 0 { // a second block, or text after the first
		return nil, true
	}
	return block.Bytes, false
}

func refPrivate(b []byte) (ed25519.PrivateKey, bool) {
	der, rejected := refBlock(b, "PRIVATE KEY")
	if rejected {
		return nil, true
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, true
	}
	priv, ok := k.(ed25519.PrivateKey)
	return priv, !ok
}

func refPublic(b []byte) (ed25519.PublicKey, bool) {
	der, rejected := refBlock(b, "PUBLIC KEY")
	if rejected {
		return nil, true
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, true
	}
	pub, ok := k.(ed25519.PublicKey)
	return pub, !ok
}
