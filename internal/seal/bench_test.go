package seal

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/netstar-labs/keystore/internal/kdf"
)

func benchAAD() []byte {
	p := kdf.Params{Algo: kdf.Algo, Mem: 64 * 1024, Time: 3, Par: 1, Salt: bytes.Repeat([]byte{1}, kdf.SaltLen)}
	return AAD("keystore/v1", "ed25519", "production-signing-key", bytes.Repeat([]byte{2}, 44), p)
}

// 32 B is a seed (the secret size); 1 KiB and 64 KiB bracket MaxSecretSize (64 KiB).
var benchSizes = []int{32, 1 << 10, 64 << 10}

func sizeName(n int) string {
	if n >= 1<<10 {
		return fmt.Sprintf("%dKiB", n>>10)
	}
	return fmt.Sprintf("%dB", n)
}

func BenchmarkSeal(b *testing.B) {
	key := bytes.Repeat([]byte{7}, kdf.KeyLen)
	aad := benchAAD()
	for _, n := range benchSizes {
		b.Run(sizeName(n), func(b *testing.B) {
			pt := bytes.Repeat([]byte{3}, n)
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, _, err := Seal(key, pt, aad); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkOpen(b *testing.B) {
	key := bytes.Repeat([]byte{7}, kdf.KeyLen)
	aad := benchAAD()
	for _, n := range benchSizes {
		b.Run(sizeName(n), func(b *testing.B) {
			nonce, ct, err := Seal(key, bytes.Repeat([]byte{3}, n), aad)
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := Open(key, nonce, ct, aad); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkAAD(b *testing.B) {
	p := kdf.Params{Algo: kdf.Algo, Mem: 64 * 1024, Time: 3, Par: 1, Salt: bytes.Repeat([]byte{1}, kdf.SaltLen)}
	pub := bytes.Repeat([]byte{2}, 44)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = AAD("keystore/v1", "ed25519", "production-signing-key", pub, p)
	}
}
