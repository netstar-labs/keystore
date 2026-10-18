package ringfile

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/netstar-labs/keystore/internal/kdf"
)

// The fixtures under ../../testdata were rendered by an independent writer (Python's
// json.dumps(indent=2) over the schema in docs/format.md), not by Marshal, so these tests
// compare the real encoder with a second implementation of the documented layout. They
// pin what TestGolden (pkg/keystore) does not: the exact bytes the WRITER emits.

const writerFormatBreak = "RING WRITER OUTPUT CHANGED (%s). Old binaries read this file with the old schema: " +
	"a renamed or reordered field is rejected whole (unknown field), but a changed value encoding (base64 variant, " +
	"timestamp form, an omitted-vs-empty `pub`) is read as a different value. The ring format is keystore/v1; a layout " +
	"change needs keystore/v2 and an upgrade path, not an edited v1. Do not re-record the fixture to make the test pass."

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func seq(from, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(from + i)
	}
	return b
}

// goldenWriterFile builds, by hand and with no clock or randomness, a ring that touches
// every writer rule: a signing entry with pub, a secret entry (pub omitted) at the
// maximum KDF parameters, a non-UTC created time (written as UTC), the current marker.
func goldenWriterFile() *File {
	spki, _ := hex.DecodeString("302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	return &File{Current: "sign-1", Entries: []Entry{
		{ID: "sign-1", Kind: KindEd25519, Pub: spki,
			KDF:   kdf.Params{Algo: kdf.Algo, Mem: 65536, Time: 3, Par: 1, Salt: seq(0, 16)},
			Nonce: seq(32, 12), CT: seq(64, 48), Created: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)},
		{ID: "api.token", Kind: KindSecret,
			KDF:   kdf.Params{Algo: kdf.Algo, Mem: kdf.MaxMem, Time: kdf.MaxTime, Par: kdf.MaxPar, Salt: seq(16, 16)},
			Nonce: seq(44, 12), CT: seq(112, 16),
			Created: time.Date(2026, 10, 18, 15, 30, 5, 0, time.FixedZone("x", 2*3600))},
	}}
}

func TestMarshalGoldenBytes(t *testing.T) {
	for _, c := range []struct {
		name string
		file *File
		want string
	}{
		{"two entries", goldenWriterFile(), "ring-two-entries.ks"},
		{"empty ring", &File{}, "ring-empty.ks"},
	} {
		got, err := Marshal(c.file)
		if err != nil {
			t.Fatal(err)
		}
		if want := fixture(t, c.want); !bytes.Equal(got, want) {
			t.Errorf(writerFormatBreak+"\n got:\n%s\nwant:\n%s", c.name, got, want)
		}
	}
}

// The committed golden ring, written by an old build, must re-encode to the identical
// bytes: today's writer rewrites every old ring on each mutation, so any drift here
// silently reformats (or worse, re-interprets) every ring in the field.
func TestMarshalReproducesGoldenRing(t *testing.T) {
	want := fixture(t, "golden.ks")
	f, err := Parse(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf(writerFormatBreak+"\n got:\n%s\nwant:\n%s", "testdata/golden.ks re-marshalled", got, want)
	}
}

// Read-side edge fixtures: each must parse, and each must have the documented shape.
func TestParseEdgeFixtures(t *testing.T) {
	for _, c := range []struct {
		file    string
		current string
		ids     []string
	}{
		{"ring-minimal.ks", "", nil},                           // {"magic":"keystore/v1"}: entries absent is an empty ring
		{"ring-empty.ks", "", nil},                             // what Create writes
		{"ring-secret-only.ks", "", []string{"golden-secret"}}, // no signing key, so current is ""
		{"ring-two-entries.ks", "sign-1", []string{"sign-1", "api.token"}},
	} {
		f, err := Parse(fixture(t, c.file))
		if err != nil {
			t.Errorf("%s: %v", c.file, err)
			continue
		}
		var ids []string
		for _, e := range f.Entries {
			ids = append(ids, e.ID)
		}
		if f.Current != c.current || len(ids) != len(c.ids) || (len(ids) > 0 && ids[0] != c.ids[0]) || f.Entries == nil {
			t.Errorf("%s: current %q entries %v, want %q %v (non-nil)", c.file, f.Current, ids, c.current, c.ids)
		}
	}
	// A minimal ring is re-written in the canonical, explicit form.
	f, _ := Parse(fixture(t, "ring-minimal.ks"))
	if b, _ := Marshal(f); !bytes.Equal(b, fixture(t, "ring-empty.ks")) {
		t.Errorf("minimal ring did not canonicalise to ring-empty.ks:\n%s", b)
	}
}
