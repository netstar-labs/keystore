package ringfile

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netstar-labs/keystore/internal/kdf"
)

func entry(t testing.TB, id, kind string) Entry {
	t.Helper()
	e := Entry{
		ID:   id,
		Kind: kind,
		KDF: kdf.Params{Algo: kdf.Algo, Mem: kdf.MinMem, Time: 1, Par: 1,
			Salt: bytes.Repeat([]byte{1}, kdf.SaltLen)},
		Nonce:   bytes.Repeat([]byte{2}, 12),
		CT:      bytes.Repeat([]byte{3}, 48),
		Created: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC),
	}
	if kind == KindEd25519 {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		e.Pub = der
	}
	return e
}

func sample(t testing.TB) *File {
	return &File{Current: "sign", Entries: []Entry{entry(t, "sign", KindEd25519), entry(t, "sec", KindSecret)}}
}

func TestMarshalParseRoundTrip(t *testing.T) {
	f := sample(t)
	b, err := Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	g, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse(Marshal(f)) = %v", err)
	}
	b2, _ := Marshal(g)
	if !bytes.Equal(b, b2) {
		t.Fatalf("not canonical:\n%s\n---\n%s", b, b2)
	}
	if g.Current != "sign" || len(g.Entries) != 2 || g.Find("sec").Kind != KindSecret {
		t.Fatalf("round trip lost data: %+v", g)
	}
}

func TestParseRejects(t *testing.T) {
	good, _ := Marshal(sample(t))
	s := string(good)
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", ErrBadFormat},
		{"not json", "hello", ErrBadFormat},
		{"wrong magic", strings.Replace(s, Magic, "other/v1", 1), ErrBadFormat},
		{"no magic", `{"current":"","entries":[]}`, ErrBadFormat},
		{"future", strings.Replace(s, Magic, "keystore/v2", 1), ErrFutureVersion},
		{"future 10", `{"magic":"keystore/v10"}`, ErrFutureVersion},
		{"v0 is not future", `{"magic":"keystore/v0"}`, ErrBadFormat},
		{"unknown field", strings.Replace(s, `"current"`, `"extra":1,"current"`, 1), ErrBadFormat},
		{"trailing data", s + "{}", ErrBadFormat},
		{"duplicate id", strings.Replace(s, `"id": "sec"`, `"id": "sign"`, 1), ErrBadFormat},
		{"bad id", strings.Replace(s, `"id": "sec"`, `"id": "-sec"`, 1), ErrBadFormat},
		{"unknown kind", strings.Replace(s, `"kind": "secret"`, `"kind": "license"`, 1), ErrBadFormat},
		{"kdf algo", strings.Replace(s, `"algo": "argon2id"`, `"algo": "pbkdf2"`, 1), ErrBadFormat},
		{"kdf mem low", strings.Replace(s, `"mem": 8192`, `"mem": 8191`, 1), ErrBadFormat},
		{"kdf mem huge", strings.Replace(s, `"mem": 8192`, `"mem": 4294967295`, 1), ErrBadFormat},
		{"kdf time 0", strings.Replace(s, `"time": 1`, `"time": 0`, 1), ErrBadFormat},
		{"kdf par 0", strings.Replace(s, `"par": 1`, `"par": 0`, 1), ErrBadFormat},
		{"kdf par overflow", strings.Replace(s, `"par": 1`, `"par": 300`, 1), ErrBadFormat},
		{"created", strings.Replace(s, "2026-10-18T12:00:00Z", "yesterday", 1), ErrBadFormat},
		{"dangling current", strings.Replace(s, `"current": "sign"`, `"current": "gone"`, 1), ErrBadFormat},
		{"current is secret", strings.Replace(s, `"current": "sign"`, `"current": "sec"`, 1), ErrBadFormat},
		{"oversize", strings.Repeat(" ", MaxSize+1), ErrBadFormat},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse([]byte(c.in)); !errors.Is(err, c.want) {
				t.Fatalf("Parse = %v, want %v", err, c.want)
			}
		})
	}
}

func TestParseRejectsFieldShapes(t *testing.T) {
	mut := map[string]func(*Entry){
		"short nonce":    func(e *Entry) { e.Nonce = e.Nonce[:11] },
		"short ct":       func(e *Entry) { e.CT = e.CT[:15] },
		"short salt":     func(e *Entry) { e.KDF.Salt = e.KDF.Salt[:15] },
		"garbage pub":    func(e *Entry) { e.Pub = []byte("not a key") },
		"missing pub":    func(e *Entry) { e.Pub = nil },
		"secret has pub": func(e *Entry) { e.Kind = KindSecret },
	}
	for name, m := range mut {
		t.Run(name, func(t *testing.T) {
			f := &File{Entries: []Entry{entry(t, "k", KindEd25519)}}
			m(&f.Entries[0])
			b, _ := Marshal(f)
			if _, err := Parse(b); !errors.Is(err, ErrBadFormat) {
				t.Fatalf("Parse = %v, want ErrBadFormat", err)
			}
		})
	}
	// A P-256 SPKI is a valid public key but not ed25519.
	f := &File{Entries: []Entry{entry(t, "k", KindEd25519)}}
	f.Entries[0].Pub = ecSPKI
	b, _ := Marshal(f)
	if _, err := Parse(b); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("non-ed25519 SPKI accepted: %v", err)
	}
}

func TestCreateNeverReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.ks")
	if err := Create(path, &File{}); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", st.Mode().Perm())
	}
	before, _ := os.ReadFile(path)
	if err := Create(path, sample(t)); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second Create = %v, want ErrExist", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("Create replaced an existing ring")
	}
	assertNoTemps(t, filepath.Dir(path))
}

func TestUpdateConcurrentNoLostWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.ks")
	if err := Create(path, &File{}); err != nil {
		t.Fatal(err)
	}
	const n = 24
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := entry(t, fmt.Sprintf("k%d", i), KindSecret)
			_, err := Update(path, func(f *File) error {
				f.Entries = append(f.Entries, e)
				return nil
			})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	f, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Entries) != n {
		t.Fatalf("%d entries after %d concurrent adds: lost writes", len(f.Entries), n)
	}
}

func TestUpdateFnErrorWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.ks")
	Create(path, sample(t))
	before, _ := os.ReadFile(path)
	boom := errors.New("boom")
	if _, err := Update(path, func(f *File) error { f.Entries = nil; return boom }); !errors.Is(err, boom) {
		t.Fatalf("Update = %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed Update modified the ring")
	}
}

// A failure injected at each stage of Save must leave a ring that opens and is either
// the old or the new content, with no temp file left behind.
func TestSaveCrashSafety(t *testing.T) {
	for _, stage := range []string{"written", "synced", "renamed"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "r.ks")
			old := &File{Entries: []Entry{entry(t, "old", KindSecret)}}
			Create(path, old)
			oldB, _ := os.ReadFile(path)

			crash := errors.New("crash")
			hook = func(s string) error {
				if s == stage {
					return crash
				}
				return nil
			}
			defer func() { hook = nil }()

			nf := &File{Entries: []Entry{entry(t, "new", KindSecret)}}
			if err := Save(path, nf); !errors.Is(err, crash) {
				t.Fatalf("Save = %v, want injected crash", err)
			}
			hook = nil
			got, err := Read(path)
			if err != nil {
				t.Fatalf("ring does not open after crash at %s: %v", stage, err)
			}
			newB, _ := Marshal(nf)
			cur, _ := os.ReadFile(path)
			if !bytes.Equal(cur, oldB) && !bytes.Equal(cur, newB) {
				t.Fatalf("ring is neither old nor new after crash at %s: %+v", stage, got)
			}
			assertNoTemps(t, dir)
		})
	}
}

func TestLockTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.ks")
	Create(path, &File{})
	release, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	old := LockTimeout
	LockTimeout = 50 * time.Millisecond
	defer func() { LockTimeout = old }()
	if _, err := Update(path, func(*File) error { return nil }); !errors.Is(err, ErrLocked) {
		t.Fatalf("Update while locked = %v, want ErrLocked", err)
	}
	st, _ := os.Stat(path + ".lock")
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode = %v", st.Mode().Perm())
	}
}

func TestLockRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.ks")
	target := filepath.Join(dir, "elsewhere")
	os.WriteFile(target, nil, 0o644)
	if err := os.Symlink(target, path+".lock"); err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(path); err == nil {
		t.Fatal("Lock followed a symlinked lock file")
	}
}

func TestSaveMode0600EvenOverWiderFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.ks")
	b, _ := Marshal(&File{})
	os.WriteFile(path, b, 0o644)
	if _, err := Update(path, func(*File) error { return nil }); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode after save = %v, want 0600", st.Mode().Perm())
	}
}

func FuzzParse(f *testing.F) {
	good, _ := Marshal(sample(f))
	f.Add(good)
	f.Add([]byte(`{"magic":"keystore/v1","current":"","entries":[]}`))
	f.Add([]byte(`{"magic":"keystore/v9"}`))
	f.Add([]byte(`{"magic":"keystore/v1","entries":[{"id":"a","kind":"secret","kdf":{"mem":4294967295}}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := Parse(b)
		if err != nil {
			return
		}
		// Anything accepted must be within bounds and re-encode to something that parses.
		for _, e := range r.Entries {
			if e.KDF.Check() != nil {
				t.Fatalf("accepted out-of-range KDF %+v", e.KDF)
			}
		}
		out, err := Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(out); err != nil {
			t.Fatalf("re-encoded ring does not parse: %v", err)
		}
	})
}

func assertNoTemps(t *testing.T, dir string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

// ecSPKI is a P-256 public key in SPKI DER: a valid key, but not ed25519.
var ecSPKI = func() []byte {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	b, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		panic(err)
	}
	return b
}()
