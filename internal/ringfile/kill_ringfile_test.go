package ringfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// padTo returns b followed by spaces up to exactly n bytes (JSON allows trailing
// whitespace, so the padded ring is still a valid ring).
func padTo(t *testing.T, b []byte, n int) []byte {
	t.Helper()
	if len(b) > n {
		t.Fatalf("ring is already %d bytes", len(b))
	}
	return append(append([]byte(nil), b...), bytes.Repeat([]byte{' '}, n-len(b))...)
}

// The size cap is 16 MiB exactly: the number is part of the format's bounds (scope.md
// property 7), so it is spelled as a literal here rather than through MaxSize, which a
// changed constant would drag along with it.
func TestParseAndReadSizeCapIsExactly16MiB(t *testing.T) {
	const limit = 16777216
	good, err := Marshal(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(padTo(t, good, limit)); err != nil {
		t.Errorf("Parse of a ring of exactly 16 MiB: %v", err)
	}
	if _, err := Parse(padTo(t, good, limit+1)); !errors.Is(err, ErrBadFormat) {
		t.Errorf("Parse of a ring of 16 MiB + 1: %v, want ErrBadFormat", err)
	}
	dir := t.TempDir()
	atCap, over := filepath.Join(dir, "at.ks"), filepath.Join(dir, "over.ks")
	if err := os.WriteFile(atCap, padTo(t, good, limit), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(over, padTo(t, good, limit+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(atCap); err != nil {
		t.Errorf("Read of a ring of exactly 16 MiB: %v", err)
	}
	// Read stops reading one byte past the cap; it must still notice that byte, not
	// truncate the file to a valid ring.
	if _, err := Read(over); !errors.Is(err, ErrBadFormat) {
		t.Errorf("Read of a ring of 16 MiB + 1: %v, want ErrBadFormat", err)
	}
}

func TestDecodeFieldLengthBoundaries(t *testing.T) {
	ok := func(name string, mut func(*Entry)) {
		t.Helper()
		f := &File{Entries: []Entry{entry(t, "k", KindSecret)}}
		mut(&f.Entries[0])
		b, err := marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(b); err != nil {
			t.Errorf("%s: Parse = %v, want nil", name, err)
		}
	}
	bad := func(name string, mut func(*Entry)) {
		t.Helper()
		f := &File{Entries: []Entry{entry(t, "k", KindSecret)}}
		mut(&f.Entries[0])
		b, err := marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(b); !errors.Is(err, ErrBadFormat) {
			t.Errorf("%s: Parse = %v, want ErrBadFormat", name, err)
		}
	}
	ok("ct of exactly the tag length (empty plaintext)", func(e *Entry) { e.CT = bytes.Repeat([]byte{3}, 16) })
	bad("ct one byte short of the tag", func(e *Entry) { e.CT = bytes.Repeat([]byte{3}, 15) })
	bad("empty ct", func(e *Entry) { e.CT = nil })
	ok("nonce of 12", func(e *Entry) { e.Nonce = bytes.Repeat([]byte{2}, 12) })
	bad("nonce of 13", func(e *Entry) { e.Nonce = bytes.Repeat([]byte{2}, 13) })
	bad("nonce of 11", func(e *Entry) { e.Nonce = bytes.Repeat([]byte{2}, 11) })
	bad("nonce of 0", func(e *Entry) { e.Nonce = nil })
	bad("salt of 17", func(e *Entry) { e.KDF.Salt = bytes.Repeat([]byte{1}, 17) })
	bad("secret carrying a one-byte pub", func(e *Entry) { e.Pub = []byte{1} })
}

// A malformed public key and a well-formed key of the wrong algorithm are different
// faults and say so; ignoring the first parse error would still reject, but under the
// other message.
func TestDecodeSaysWhichPublicKeyFaultItFound(t *testing.T) {
	for name, c := range map[string]struct {
		pub  []byte
		want string
	}{
		"garbage":     {[]byte("not a key"), "bad public key"},
		"p256":        {ecSPKI, "not ed25519"},
		"empty pub":   {nil, "bad public key"},
		"truncated":   {entry(t, "k", KindEd25519).Pub[:20], "bad public key"},
		"extra bytes": {append(entry(t, "k", KindEd25519).Pub, 0), "bad public key"},
	} {
		f := &File{Entries: []Entry{entry(t, "k", KindEd25519)}}
		f.Entries[0].Pub = c.pub
		b, _ := marshal(f)
		_, err := Parse(b)
		if !errors.Is(err, ErrBadFormat) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Parse = %v, want ErrBadFormat mentioning %q", name, err, c.want)
		}
	}
}

// "keystore/v01" is not a newer format; only a version number above 1 is.
func TestFutureVersionIsOnlyAboveOne(t *testing.T) {
	for magic, want := range map[string]error{
		"keystore/v1":   nil,
		"keystore/v01":  ErrBadFormat,
		"keystore/v2":   ErrFutureVersion,
		"keystore/v02":  ErrFutureVersion,
		"keystore/v100": ErrFutureVersion,
		"keystore/v0":   ErrBadFormat,
		"keystore/v-1":  ErrBadFormat,
		"keystore/vx":   ErrBadFormat,
		"keystore/v":    ErrBadFormat,
		"keystore/":     ErrBadFormat,
	} {
		_, err := Parse([]byte(`{"magic":"` + magic + `","entries":[]}`))
		if want == nil && err != nil || want != nil && !errors.Is(err, want) {
			t.Errorf("magic %q: Parse = %v, want %v", magic, err, want)
		}
	}
}

// A repeated "entries" key follows encoding/json: the last one wins, and the earlier
// array's entries are not kept (each occurrence is validated on its own).
func TestRepeatedEntriesKeyLastWins(t *testing.T) {
	one, _ := Marshal(&File{Entries: []Entry{entry(t, "first", KindSecret)}})
	two, _ := Marshal(&File{Entries: []Entry{entry(t, "second", KindSecret)}})
	arr := func(b []byte) string {
		s := string(b)
		i := strings.Index(s, `"entries":`)
		return strings.TrimSpace(s[i+len(`"entries":`) : strings.LastIndex(s, "}")])
	}
	doc := `{"magic":"keystore/v1","current":"","entries":` + arr(one) + `,"entries":` + arr(two) + `}`
	f, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse = %v", err)
	}
	if len(f.Entries) != 1 || f.Entries[0].ID != "second" {
		t.Fatalf("entries = %+v, want only the last array's entry", f.Entries)
	}
}

// The canonical encoding: UTC timestamps, two-space indent, one trailing newline. Bytes
// that other tools (and the golden file) rely on.
func TestMarshalCanonicalForm(t *testing.T) {
	f := &File{Entries: []Entry{entry(t, "k", KindSecret)}}
	f.Entries[0].Created = time.Date(2026, 10, 18, 14, 0, 0, 0, time.FixedZone("x", 2*3600))
	b, err := Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"created": "2026-10-18T12:00:00Z"`) {
		t.Errorf("created not written in UTC:\n%s", s)
	}
	if !strings.HasPrefix(s, "{\n  \"magic\": \"keystore/v1\",\n  \"current\": \"\",\n  \"entries\": [\n    {\n      \"id\": \"k\",") {
		t.Errorf("not two-space indented:\n%s", s)
	}
	if !strings.HasSuffix(s, "}\n") || strings.HasSuffix(s, "}\n\n") {
		t.Errorf("want exactly one trailing newline, got %q", s[len(s)-4:])
	}
	g, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.Entries[0].Created.Location() != time.UTC {
		t.Errorf("parsed created in %v, want UTC", g.Entries[0].Created.Location())
	}
}

func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Skipf("cannot list descriptors: %v", err)
	}
	return len(ents)
}

// Read, Lock/release, Update and Create must give back every descriptor they open: a
// long-running embedder (the agent, a service) calls them for the life of the process.
func TestNoDescriptorLeak(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.ks")
	if err := Create(path, sample(t)); err != nil {
		t.Fatal(err)
	}
	cycle := func() {
		if _, err := Read(path); err != nil {
			t.Fatal(err)
		}
		release, err := Lock(path)
		if err != nil {
			t.Fatal(err)
		}
		release()
		if _, err := Update(path, func(*File) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	cycle() // warm up anything the runtime opens lazily
	before := openFDs(t)
	for i := 0; i < 50; i++ {
		cycle()
	}
	if after := openFDs(t); after > before+2 {
		t.Fatalf("%d descriptors open after 50 cycles, %d before: leak", after, before)
	}
}
