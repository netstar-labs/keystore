package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netstar-labs/keystore/internal/kdf"
	"github.com/netstar-labs/keystore/pkg/keystore"
)

// These benchmarks drive run(...) in-process at the MINIMUM KDF cost (set explicitly
// here and restored, so they do not depend on TestMain). The numbers are therefore NOT
// production latencies: at the shipped cost every unlock is on the order of 140 ms (one light-load sample on an M1 Pro), which these
// numbers omit. They measure everything else (flag parsing, ring I/O, signing, output).
// The one real-cost end-to-end figure is recorded in docs/audits/benchmark-baselines.md.
func lowCost(b *testing.B) {
	old := kdf.Default
	kdf.Default = kdf.Cost{Mem: kdf.MinMem, Time: kdf.MinTime, Par: kdf.MinPar}
	b.Setenv("KEYSTORE_PASSPHRASE", testPass)
	b.Cleanup(func() { kdf.Default = old })
}

// benchRing makes a ring of n signing keys (the first current) and returns its path.
func benchRing(b *testing.B, n int) string {
	path := filepath.Join(b.TempDir(), "r.ks")
	k, err := keystore.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	for i := range n {
		if _, err := k.Add("key"+string(rune('a'+i%26))+strings.Repeat("x", i/26), []byte(testPass)); err != nil {
			b.Fatal(err)
		}
	}
	return path
}

func BenchmarkRunSign(b *testing.B) {
	lowCost(b)
	ring := benchRing(b, 1)
	msg := filepath.Join(b.TempDir(), "msg")
	if err := os.WriteFile(msg, bytes.Repeat([]byte{0x5a}, 64), 0o600); err != nil {
		b.Fatal(err)
	}
	args := []string{"sign", "-keystore", ring, "-in", msg}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		var out bytes.Buffer
		if err := run(args, &stdio{in: strings.NewReader(""), out: &out, err: io.Discard}); err != nil {
			b.Fatal(err)
		}
		if out.Len() == 0 {
			b.Fatal("no signature written")
		}
	}
}

func BenchmarkRunList(b *testing.B) {
	for _, n := range []struct {
		name string
		n    int
	}{{"entries=1", 1}, {"entries=20", 20}} {
		b.Run(n.name, func(b *testing.B) {
			lowCost(b)
			ring := benchRing(b, n.n)
			args := []string{"list", "-keystore", ring}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				var out bytes.Buffer
				if err := run(args, &stdio{in: strings.NewReader(""), out: &out, err: io.Discard}); err != nil {
					b.Fatal(err)
				}
				if bytes.Count(out.Bytes(), []byte{'\n'}) != n.n {
					b.Fatalf("list wrote %d lines, want %d", bytes.Count(out.Bytes(), []byte{'\n'}), n.n)
				}
			}
		})
	}
}
