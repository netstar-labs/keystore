package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/netstar-labs/keystore/internal/kdf"
	"github.com/netstar-labs/keystore/internal/ringfile"
)

// The suite's TestMain lowers kdf.Default to the minimum so tests are fast. The
// benchmarks that involve the KDF therefore set the cost they mean, explicitly, and
// restore it: "production" mirrors kdf.Default as shipped (64 MiB, 3 passes, 1 lane;
// if that constant is ever changed deliberately, change it here and re-record the
// baselines), "minimum" is the test-suite cost and shows what is left once the KDF is
// almost free (ring I/O, AEAD, encoding).
var benchCosts = []struct {
	name string
	cost kdf.Cost
}{
	{"production", kdf.Cost{Mem: 64 * 1024, Time: 3, Par: 1}},
	{"minimum", kdf.Cost{Mem: kdf.MinMem, Time: kdf.MinTime, Par: kdf.MinPar}},
}

func withCost(b *testing.B, c kdf.Cost) {
	old := kdf.Default
	kdf.Default = c
	b.Cleanup(func() { kdf.Default = old })
}

var (
	tmplMu sync.Mutex
	tmpls  = map[string][]byte{}
)

// template returns the bytes of a ring of n signing entries encrypted under pass at the
// current kdf.Default. Building it costs ~2 KDF runs per entry, so it is done once per
// (cost, n) per process and kept outside every timed region.
func template(b *testing.B, n int) []byte {
	key := fmt.Sprintf("%v/%d", kdf.Default, n)
	tmplMu.Lock()
	defer tmplMu.Unlock()
	if t, ok := tmpls[key]; ok {
		return t
	}
	dir, err := os.MkdirTemp("", "ksbench")
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "r.ks")
	k, err := Create(path)
	if err != nil {
		b.Fatal(err)
	}
	for i := range n {
		if _, err := k.Add(fmt.Sprintf("key-%d", i), pass); err != nil {
			b.Fatal(err)
		}
	}
	t, err := os.ReadFile(path)
	if err != nil {
		b.Fatal(err)
	}
	tmpls[key] = t
	return t
}

// fresh writes a copy of the template to a new directory and opens it.
func fresh(b *testing.B, n int) *Keystore {
	path := filepath.Join(b.TempDir(), "r.ks")
	if err := os.WriteFile(path, template(b, n), 0o600); err != nil {
		b.Fatal(err)
	}
	k, err := Open(path)
	if err != nil {
		b.Fatal(err)
	}
	return k
}

// bigRingFile writes a ring of n signing entries with placeholder ciphertext (valid in
// shape, never decrypted) and returns its path: the KDF is not involved in Open or List.
func bigRingFile(b *testing.B, n int) string {
	f := &ringfile.File{}
	for i := range n {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			b.Fatal(err)
		}
		f.Entries = append(f.Entries, ringfile.Entry{
			ID: fmt.Sprintf("key-%d", i), Kind: ringfile.KindEd25519, Pub: der,
			KDF:     kdf.Params{Algo: kdf.Algo, Mem: kdf.MinMem, Time: 1, Par: 1, Salt: make([]byte, kdf.SaltLen)},
			Nonce:   make([]byte, 12),
			CT:      make([]byte, 64),
			Created: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC),
		})
	}
	f.Current = "key-0"
	path := filepath.Join(b.TempDir(), "big.ks")
	if err := ringfile.Create(path, f); err != nil {
		b.Fatal(err)
	}
	return path
}

// BenchmarkOpenList is Open (read + Parse) plus List (SPKI parse and fingerprint per
// signing entry) on a large ring. Neither touches the KDF.
func BenchmarkOpenList(b *testing.B) {
	for _, n := range []int{10, 1000} {
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			path := bigRingFile(b, n)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				k, err := Open(path)
				if err != nil {
					b.Fatal(err)
				}
				if got := len(k.List()); got != n {
					b.Fatalf("List = %d entries, want %d", got, n)
				}
			}
		})
	}
}

// BenchmarkList isolates List from Open.
func BenchmarkList(b *testing.B) {
	k, err := Open(bigRingFile(b, 1000))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = k.List()
	}
}

// BenchmarkAdd adds one key to a ring that already holds one. At production cost it is
// dominated by exactly two KDF runs: checkPassphrase unlocks the first entry (run 1)
// and encrypt derives the new entry's key (run 2); expect ~2x BenchmarkDerive/production
// plus the durable Save. The ring is restored from the template outside the timer.
func BenchmarkAdd(b *testing.B) {
	for _, c := range benchCosts {
		b.Run(c.name, func(b *testing.B) {
			withCost(b, c.cost)
			template(b, 1) // built once, untimed
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				k := fresh(b, 1)
				b.StartTimer()
				if _, err := k.Add("added", pass); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkSigner is one unlock: one KDF run plus AEAD open, PKCS#8 parse and the
// public-key cross-check. This is the cost `keystore sign` pays without an agent.
func BenchmarkSigner(b *testing.B) {
	for _, c := range benchCosts {
		b.Run(c.name, func(b *testing.B) {
			withCost(b, c.cost)
			k := fresh(b, 1)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := k.Signer("", pass); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkChangePassphrase re-encrypts N entries: N unlocks plus N fresh encryptions,
// 2N KDF runs, so it is linear in N (N=8 should cost ~4x N=2; the table in
// docs/audits/benchmark-baselines.md records the ratio). Passphrases alternate each
// iteration so the ring never needs resetting.
func BenchmarkChangePassphrase(b *testing.B) {
	other := []byte("a different benchmark passphrase")
	for _, c := range benchCosts {
		for _, n := range []int{2, 8} {
			b.Run(fmt.Sprintf("%s/entries=%d", c.name, n), func(b *testing.B) {
				withCost(b, c.cost)
				k := fresh(b, n)
				from, to := pass, other
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if err := k.ChangePassphrase(from, to); err != nil {
						b.Fatal(err)
					}
					from, to = to, from
				}
			})
		}
	}
}

func BenchmarkFingerprint(b *testing.B) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if Fingerprint(pub) == "" {
			b.Fatal("empty fingerprint")
		}
	}
}
