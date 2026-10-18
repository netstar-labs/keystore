package ringfile

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

var ringSizes = []int{1, 10, 100, 1000, 10000}

var (
	benchMu    sync.Mutex
	benchRings = map[int]*File{}
)

// benchRing builds (once per size, outside any timed region) a ring of n signing
// entries using the package's own test helper, so the bytes are exactly what Marshal
// writes in production.
func benchRing(b *testing.B, n int) *File {
	benchMu.Lock()
	defer benchMu.Unlock()
	if f, ok := benchRings[n]; ok {
		return f
	}
	f := &File{}
	for i := range n {
		f.Entries = append(f.Entries, entry(b, fmt.Sprintf("key-%d", i), KindEd25519))
	}
	f.Current = "key-0"
	benchRings[n] = f
	return f
}

// perInputByte reports heap bytes allocated per input byte over b.N runs of fn. It is
// the guard for Parse's allocation behaviour: a streaming decode stays a small constant
// multiple of the file; the old whole-array decode grew without bound on hostile input.
func perInputByte(b *testing.B, inBytes int, fn func()) {
	var a, z runtime.MemStats
	runtime.ReadMemStats(&a)
	for range b.N {
		fn()
	}
	runtime.ReadMemStats(&z)
	b.ReportMetric(float64(z.TotalAlloc-a.TotalAlloc)/float64(b.N)/float64(inBytes), "allocB/inB")
}

func BenchmarkParse(b *testing.B) {
	for _, n := range ringSizes {
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			data, err := Marshal(benchRing(b, n))
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			perInputByte(b, len(data), func() {
				if _, err := Parse(data); err != nil {
					b.Fatal(err)
				}
			})
		})
	}
}

// BenchmarkParseHostileEmptyObjects is a 1 MiB array of "{}": the shape that made the
// old decode allocate a struct per element before validating any. It must fail at the
// first element, so B/op here stays tiny and independent of the input size.
func BenchmarkParseHostileEmptyObjects(b *testing.B) {
	n := (1 << 20) / 3
	body := make([]byte, 0, 3*n+64)
	body = append(body, `{"magic":"keystore/v1","current":"","entries":[`...)
	for range n {
		body = append(body, '{', '}', ',')
	}
	body = append(body, `{}]}`...)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	perInputByte(b, len(body), func() {
		if _, err := Parse(body); err == nil {
			b.Fatal("hostile ring parsed")
		}
	})
}

// Marshal includes the self-check Parse of its own output, so it costs roughly
// marshal + Parse.
func BenchmarkMarshal(b *testing.B) {
	for _, n := range ringSizes {
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			f := benchRing(b, n)
			data, err := Marshal(f)
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			perInputByte(b, len(data), func() {
				if _, err := Marshal(f); err != nil {
					b.Fatal(err)
				}
			})
		})
	}
}

// BenchmarkSave is the durable write: Marshal, temp file, fsync, rename, directory
// sync. It is dominated by the fsyncs; the numbers are the filesystem's, so compare
// only within one machine and filesystem.
func BenchmarkSave(b *testing.B) {
	for _, n := range []int{2, 100} {
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			f := benchRing(b, n)
			path := filepath.Join(b.TempDir(), "r.ks")
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := Save(path, f); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if _, err := os.Stat(path); err != nil {
				b.Fatal(err)
			}
		})
	}
}

// BenchmarkLock is an uncontended take and release of the sidecar flock.
func BenchmarkLock(b *testing.B) {
	path := filepath.Join(b.TempDir(), "r.ks")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		release, err := Lock(path)
		if err != nil {
			b.Fatal(err)
		}
		release()
	}
}
