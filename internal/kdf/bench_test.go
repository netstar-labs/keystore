package kdf

import (
	"bytes"
	"testing"
)

// Derive is the dominant cost of every unlock and every write in the module. The
// production cost is deliberate (it is the brute-force price an attacker pays per
// guess); these benchmarks only record it so that a change in either the cost constant
// or the underlying argon2 implementation is visible. A faster production number is
// never a goal.
func BenchmarkDerive(b *testing.B) {
	salt := bytes.Repeat([]byte{9}, SaltLen)
	pass := []byte("a long enough benchmark passphrase")
	for _, c := range []struct {
		name string
		cost Cost
	}{
		{"production", Default}, // read at run time: the real default (64 MiB, 3 passes, 1 lane)
		{"minimum", Cost{Mem: MinMem, Time: MinTime, Par: MinPar}},
		{"high256MiB_t3_p1", Cost{Mem: 256 * 1024, Time: 3, Par: 1}},
	} {
		b.Run(c.name, func(b *testing.B) {
			p := Params{Algo: Algo, Mem: c.cost.Mem, Time: c.cost.Time, Par: c.cost.Par, Salt: salt}
			if err := p.Check(); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := p.Derive(pass); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkNew is the parameter-set constructor (a random salt), to show it is noise
// next to Derive.
func BenchmarkNew(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		if _, err := New(); err != nil {
			b.Fatal(err)
		}
	}
}
