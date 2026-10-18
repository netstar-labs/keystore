package agent

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// benchAgent starts an in-process agent on a unix socket (short path: Darwin limits
// socket paths to ~104 bytes) and returns the socket path and the key it serves.
func benchAgent(b *testing.B) (string, ed25519.PrivateKey) {
	b.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}
	srv, err := NewServer(priv)
	if err != nil {
		b.Fatal(err)
	}
	dir, err := os.MkdirTemp("/tmp", "kb")
	if err != nil {
		b.Fatal(err)
	}
	sock := filepath.Join(dir, "agent.sock")
	ln, err := Listen(sock)
	if err != nil {
		os.RemoveAll(dir)
		b.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	b.Cleanup(func() {
		srv.Close()
		<-done
		os.RemoveAll(dir)
	})
	return sock, priv
}

var msgSizes = []struct {
	name string
	n    int
}{{"64B", 64}, {"1MiB", MaxPayload}}

// BenchmarkSignViaAgent is a full sign round trip: unix-socket dial, peer-credential
// check on both ends, request frame, Ed25519 sign in the server, reply frame, and the
// client's own verification of the returned signature. Every Sign dials a fresh
// connection (the client keeps none open), so "Dial" cost is included.
//
// The clients are exactly N goroutines splitting b.N between them. b.RunParallel is not
// used because it cannot run fewer goroutines than GOMAXPROCS, so "1 client" could not
// be expressed; the shape (N concurrent callers, wall time per op) is the same.
func BenchmarkSignViaAgent(b *testing.B) {
	for _, m := range msgSizes {
		for _, clients := range []int{1, 8, 64} {
			b.Run(fmt.Sprintf("%s/clients=%d", m.name, clients), func(b *testing.B) {
				sock, _ := benchAgent(b)
				c, err := Dial(sock)
				if err != nil {
					b.Fatal(err)
				}
				msg := bytes.Repeat([]byte{0x5a}, m.n)
				b.SetBytes(int64(m.n))
				b.ReportAllocs()
				b.ResetTimer()
				var wg sync.WaitGroup
				errs := make(chan error, clients)
				for w := range clients {
					ops := b.N / clients
					if w < b.N%clients {
						ops++
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						for range ops {
							if _, err := c.Sign(nil, msg, crypto.Hash(0)); err != nil {
								errs <- err
								return
							}
						}
					}()
				}
				wg.Wait()
				b.StopTimer()
				select {
				case err := <-errs:
					b.Fatal(err)
				default:
				}
			})
		}
	}
}

// BenchmarkSignInProcess is the floor the agent is compared against: ed25519.Sign on the
// same message, no socket. Agent overhead = BenchmarkSignViaAgent/<size>/clients=1 minus
// this, plus the client's Verify (BenchmarkVerifyInProcess).
func BenchmarkSignInProcess(b *testing.B) {
	_, priv, _ := ed25519.GenerateKey(nil)
	for _, m := range msgSizes {
		b.Run(m.name, func(b *testing.B) {
			msg := bytes.Repeat([]byte{0x5a}, m.n)
			b.SetBytes(int64(m.n))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = ed25519.Sign(priv, msg)
			}
		})
	}
}

// BenchmarkVerifyInProcess is the check Client.Sign performs on every reply.
func BenchmarkVerifyInProcess(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	for _, m := range msgSizes {
		b.Run(m.name, func(b *testing.B) {
			msg := bytes.Repeat([]byte{0x5a}, m.n)
			sig := ed25519.Sign(priv, msg)
			b.SetBytes(int64(m.n))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if !ed25519.Verify(pub, msg, sig) {
					b.Fatal("verify failed")
				}
			}
		})
	}
}

// BenchmarkDial is the public-key fetch: connect, credential checks, OpPublic frame.
func BenchmarkDial(b *testing.B) {
	sock, _ := benchAgent(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := Dial(sock); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadFrame(b *testing.B) {
	for _, m := range []struct {
		name string
		n    int
	}{{"64B", 64}, {"64KiB", 64 << 10}, {"1MiB", MaxPayload}} {
		b.Run(m.name, func(b *testing.B) {
			var buf bytes.Buffer
			if err := writeFrame(&buf, OpSign, bytes.Repeat([]byte{1}, m.n)); err != nil {
				b.Fatal(err)
			}
			wire := buf.Bytes()
			r := bytes.NewReader(wire)
			b.SetBytes(int64(m.n))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				r.Reset(wire)
				if _, _, err := readFrame(r); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkWriteFrame(b *testing.B) {
	for _, m := range []struct {
		name string
		n    int
	}{{"64B", 64}, {"64KiB", 64 << 10}, {"1MiB", MaxPayload}} {
		b.Run(m.name, func(b *testing.B) {
			p := bytes.Repeat([]byte{1}, m.n)
			b.SetBytes(int64(m.n))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := writeFrame(io.Discard, OpSign, p); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
