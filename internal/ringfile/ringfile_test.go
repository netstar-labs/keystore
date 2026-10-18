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
	"runtime"
	"strings"
	"sync"
	"syscall"
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
			b, err := marshal(f) // raw encoder: Marshal itself refuses invalid rings
			if err != nil || len(b) == 0 {
				t.Fatalf("crafting the invalid ring: %v", err)
			}
			if _, err := Parse(b); !errors.Is(err, ErrBadFormat) {
				t.Fatalf("Parse = %v, want ErrBadFormat", err)
			}
		})
	}
	// A P-256 SPKI is a valid public key but not ed25519.
	f := &File{Entries: []Entry{entry(t, "k", KindEd25519)}}
	f.Entries[0].Pub = ecSPKI
	b, _ := marshal(f)
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

// Regression (review F2): a created time whose UTC form is outside years 0000-9999
// parsed, then marshalled to something RFC 3339 cannot read back, bricking the ring on
// the next write.
func TestCreatedOutOfRangeRejected(t *testing.T) {
	good, _ := Marshal(sample(t))
	for _, c := range []string{"0000-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"} {
		in := strings.Replace(string(good), "2026-10-18T12:00:00Z", c, 1)
		if _, err := Parse([]byte(in)); !errors.Is(err, ErrBadFormat) {
			t.Errorf("created %s accepted: %v", c, err)
		}
	}
}

// Save never writes bytes that Parse would reject.
func TestMarshalRefusesInvalid(t *testing.T) {
	f := sample(t)
	f.Entries[0].Nonce = f.Entries[0].Nonce[:3]
	if _, err := Marshal(f); err == nil {
		t.Fatal("Marshal produced an invalid ring")
	}
}

func TestSaveRefusesUnreadableOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.ks")
	Create(path, sample(t))
	before, _ := os.ReadFile(path)
	f := sample(t)
	f.Entries[0].Created = time.Date(-1, 12, 31, 0, 0, 0, 0, time.UTC)
	if err := Save(path, f); err == nil {
		t.Fatal("Save wrote a ring that does not parse")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("refused Save modified the ring")
	}
	assertNoTemps(t, filepath.Dir(path))
}

// totalAlloc runs fn and reports how many bytes it allocated, measured from a settled heap.
func totalAlloc(fn func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	fn()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// A ring at the size cap made of empty objects must fail at the first one without first
// materialising every element: the file cap bounds the input, this bounds the memory.
// The limit is about 3x what the streaming decode allocates (32 MiB observed); the old
// decode allocated about 7 GiB.
func TestParseDoesNotAmplify(t *testing.T) {
	n := (MaxSize - 128) / 3 // "{}," is 3 bytes
	body := []byte(`{"magic":"keystore/v1","current":"","entries":[` + strings.Repeat("{},", n) + `{}]}`)
	if len(body) > MaxSize {
		t.Fatalf("test ring is %d bytes, over MaxSize", len(body))
	}
	var err error
	grew := totalAlloc(func() { _, err = Parse(body) })
	if !errors.Is(err, ErrBadFormat) {
		t.Fatalf("Parse = %v, want ErrBadFormat", err)
	}
	if grew > 96<<20 {
		t.Fatalf("Parse of a %d MiB ring allocated %d MiB", len(body)>>20, grew>>20)
	}
}

func bigRing(t *testing.T, n int) *File {
	f := &File{}
	for i := range n {
		f.Entries = append(f.Entries, entry(t, fmt.Sprintf("k%d", i), KindSecret))
	}
	return f
}

func TestParseLargeValidRing(t *testing.T) {
	f := bigRing(t, 5000)
	b, err := Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	g, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse(Marshal(f)) = %v", err)
	}
	if len(g.Entries) != 5000 || g.Find("k4999") == nil {
		t.Fatalf("lost entries: %d", len(g.Entries))
	}
	b2, _ := Marshal(g)
	if !bytes.Equal(b, b2) {
		t.Fatal("not canonical")
	}
	// Allocation stays proportional to the ring, not a multiple of it.
	if grew := totalAlloc(func() { Parse(b) }); grew > uint64(len(b))*16 {
		t.Fatalf("Parse of %d bytes allocated %d bytes", len(b), grew)
	}
}

func TestParseReportsFirstBadEntryInLargeRing(t *testing.T) {
	b, err := Marshal(bigRing(t, 5000))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	// Two bad entries; the earlier one (2500) is the one reported.
	s = strings.Replace(s, `"id": "k2500"`, `"id": "-bad"`, 1)
	s = strings.Replace(s, `"id": "k4000"`, `"id": "-worse"`, 1)
	_, err = Parse([]byte(s))
	if !errors.Is(err, ErrBadFormat) || !strings.Contains(err.Error(), "entry 2500:") {
		t.Fatalf("Parse = %v, want ErrBadFormat at entry 2500", err)
	}
	// A duplicate id deep in the ring is still caught, with its index.
	d := strings.Replace(string(b), `"id": "k3000"`, `"id": "k17"`, 1)
	_, err = Parse([]byte(d))
	if !errors.Is(err, ErrBadFormat) || !strings.Contains(err.Error(), "entry 3000: duplicate id") {
		t.Fatalf("Parse = %v, want duplicate id at entry 3000", err)
	}
}

func TestParseEntriesShapes(t *testing.T) {
	good, _ := Marshal(sample(t))
	for name, c := range map[string]struct {
		in      string
		entries int
		bad     bool
	}{
		"missing":                {`{"magic":"keystore/v1"}`, 0, false},
		"null":                   {`{"magic":"keystore/v1","entries":null}`, 0, false},
		"empty":                  {`{"magic":"keystore/v1","entries":[]}`, 0, false},
		"null elem":              {`{"magic":"keystore/v1","entries":[null]}`, 0, true},
		"not array":              {`{"magic":"keystore/v1","entries":{}}`, 0, true},
		"scalar":                 {`{"magic":"keystore/v1","entries":[1]}`, 0, true},
		"unknown field in entry": {strings.Replace(string(good), `"kind"`, `"extra":1,"kind"`, 1), 0, true},
		"trailing after entries": {strings.TrimSpace(string(good)) + `[]`, 0, true},
	} {
		t.Run(name, func(t *testing.T) {
			f, err := Parse([]byte(c.in))
			if c.bad {
				if !errors.Is(err, ErrBadFormat) {
					t.Fatalf("Parse = %v, want ErrBadFormat", err)
				}
				return
			}
			if err != nil || len(f.Entries) != c.entries {
				t.Fatalf("Parse = %v, %v", f, err)
			}
			if f.Entries == nil {
				t.Fatal("Entries is nil; a ring with no entries yields a non-nil empty slice")
			}
		})
	}
	// A valid ring with a second `entries` key appended is rejected for the duplicate key,
	// whatever the second array holds (here one invalid element).
	dup := strings.TrimSpace(string(good))
	dup = dup[:len(dup)-1] + `,"entries":[{}]}`
	if _, err := Parse([]byte(dup)); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("valid ring plus a second entries key: %v", err)
	}
	// A second `entries` key is rejected outright (even an empty one, in any case): each
	// occurrence cost a fresh Decoder, so 16 MiB of `"entries":[],` was accepted at ~1.9 s
	// and ~786 MiB of garbage. Rejecting at the second key makes the cost constant.
	for _, d := range []string{
		`{"magic":"keystore/v1","entries":[],"entries":[]}`,
		`{"magic":"keystore/v1","entries":[],"Entries":null}`,
		`{"magic":"keystore/v1","entries":null,"entries":[]}`,
	} {
		if _, err := Parse([]byte(d)); !errors.Is(err, ErrBadFormat) {
			t.Fatalf("Parse(%s) = %v, want ErrBadFormat", d, err)
		}
	}
	ring := []byte(`{` + strings.Repeat(`"entries":[],`, (MaxSize-40)/13) + `"magic":"keystore/v1"}`)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := Parse(ring)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrBadFormat) {
		t.Fatalf("repeated entries key: Parse = %v, want ErrBadFormat", err)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 64<<20 {
		t.Fatalf("repeated entries key allocated %d MiB, want < 64 (the decoder buffers the input ~2x; it was ~786)", got>>20)
	}
	if _, err := Parse([]byte(`{"magic":"keystore/v1","entries":[null]}`)); !strings.Contains(fmt.Sprint(err), "invalid entry id") {
		t.Fatalf("null element: %v", err)
	}
	// A newer magic still wins over entries this binary cannot read.
	if _, err := Parse([]byte(`{"magic":"keystore/v2","entries":[{"new":1}]}`)); !errors.Is(err, ErrFutureVersion) {
		t.Fatalf("future magic with unknown entry fields: %v", err)
	}
}

// A restrictive umask made the lock file 0400 at creation, so every later open for writing
// failed ("permission denied") until the file was removed: the ring's other lock (and any
// later write) was wedged by the creator's own umask. The lock file is 0600 whatever the
// umask (the temp file already chmods explicitly).
func TestLockFileIsUsableUnderARestrictiveUmask(t *testing.T) {
	dir := t.TempDir() // before the umask change: a 0277 umask cannot even create it
	old := syscall.Umask(0o277)
	defer syscall.Umask(old)
	path := filepath.Join(dir, "r.ks")
	release, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	release()
	st, err := os.Stat(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("lock file mode %04o, want 0600", st.Mode().Perm())
	}
	release, err = Lock(path) // the second open used to fail with permission denied
	if err != nil {
		t.Fatalf("second Lock under umask 0277: %v", err)
	}
	release()
}
