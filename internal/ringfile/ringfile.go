// Package ringfile reads, validates and durably writes the ring file. It knows the
// on-disk schema and the write discipline; it knows nothing about keys or passphrases.
//
// Every mutation goes through [Update]: take the lock, re-read the file, apply the
// change to that fresh copy, write a temp file, fsync it, rename it over the ring, fsync
// the directory, release the lock. A crash at any point leaves the old ring or the new
// one, and two cooperating writers cannot lose each other's changes.
package ringfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/netstar-labs/keystore/internal/ids"
	"github.com/netstar-labs/keystore/internal/kdf"
	"github.com/netstar-labs/keystore/internal/seal"
)

// Magic is the format tag of ring files this package reads and writes.
const Magic = "keystore/v1"

const magicPrefix = "keystore/v"

// Entry kinds.
const (
	KindEd25519 = "ed25519" // PKCS#8 DER of an Ed25519 private key, encrypted
	KindSecret  = "secret"  // opaque bytes, encrypted
)

// MaxSize caps how much of a ring file is read. A real ring is a few KiB.
const MaxSize = 16 << 20

// minCT is the smallest possible ciphertext: an empty plaintext plus the GCM tag.
const minCT = 16

var (
	// ErrBadFormat reports a file that is not a valid ring of this format.
	ErrBadFormat = errors.New("keystore: not a keystore file")
	// ErrFutureVersion reports a ring written by a newer format version.
	ErrFutureVersion = errors.New("keystore: ring format is newer than this binary; upgrade it")
	// ErrLocked reports that another process held the ring lock past LockTimeout.
	ErrLocked = errors.New("keystore: ring is locked by another process")
)

// LockTimeout bounds how long Update waits for the ring lock.
var LockTimeout = 10 * time.Second

// Entry is one decoded, validated ring entry.
type Entry struct {
	ID      string
	Kind    string
	Pub     []byte // SPKI DER; ed25519 entries only
	KDF     kdf.Params
	Nonce   []byte
	CT      []byte
	Created time.Time
}

// File is a decoded, validated ring.
type File struct {
	Current string
	Entries []Entry
}

// Find returns the entry with id, or nil.
func (f *File) Find(id string) *Entry {
	for i := range f.Entries {
		if f.Entries[i].ID == id {
			return &f.Entries[i]
		}
	}
	return nil
}

// wire types: the JSON schema. []byte fields are standard base64.
type wireKDF struct {
	Algo string `json:"algo"`
	Mem  uint32 `json:"mem"`
	Time uint32 `json:"time"`
	Par  uint8  `json:"par"`
	Salt []byte `json:"salt"`
}

type wireEntry struct {
	ID      string  `json:"id"`
	Kind    string  `json:"kind"`
	Pub     []byte  `json:"pub,omitempty"`
	KDF     wireKDF `json:"kdf"`
	Nonce   []byte  `json:"nonce"`
	CT      []byte  `json:"ct"`
	Created string  `json:"created"`
}

type wireFile struct {
	Magic   string      `json:"magic"`
	Current string      `json:"current"`
	Entries []wireEntry `json:"entries"`
}

// wireEntries decodes and validates the entries array one element at a time. Decoding
// it into []wireEntry would allocate a struct per element before anything is checked,
// so a 16 MiB ring of "{}" would cost gigabytes; this fails at the first bad entry and
// allocates in proportion to the entries that are actually valid.
type wireEntries []Entry

func (es *wireEntries) UnmarshalJSON(b []byte) error {
	*es = nil // a duplicated `entries` key replaces the earlier array; each occurrence is validated
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if t, err := dec.Token(); err != nil || (t != json.Delim('[') && t != nil) {
		return ErrBadFormat // not an array; null is an empty ring, as for a slice
	}
	seen := make(map[string]bool)
	for i := 0; dec.More(); i++ {
		var we wireEntry
		if err := dec.Decode(&we); err != nil {
			return ErrBadFormat
		}
		e, err := decodeEntry(we)
		if err != nil {
			return fmt.Errorf("%w: entry %d: %v", ErrBadFormat, i, err)
		}
		if seen[e.ID] {
			return fmt.Errorf("%w: entry %d: duplicate id", ErrBadFormat, i)
		}
		seen[e.ID] = true
		*es = append(*es, e)
	}
	return nil // the outer decoder has already checked the closing bracket
}

// Parse decodes and validates a ring file. Unknown fields, trailing data, an unknown
// kind, an out-of-range KDF parameter, a malformed public key or a dangling current
// pointer are all ErrBadFormat; a newer format tag is ErrFutureVersion.
func Parse(b []byte) (*File, error) {
	if len(b) > MaxSize {
		return nil, ErrBadFormat
	}
	var peek struct {
		Magic string `json:"magic"`
	}
	if json.Unmarshal(b, &peek) != nil {
		return nil, ErrBadFormat
	}
	if peek.Magic != Magic {
		if v, ok := strings.CutPrefix(peek.Magic, magicPrefix); ok {
			if n, err := strconv.Atoi(v); err == nil && n > 1 {
				return nil, ErrFutureVersion
			}
		}
		return nil, ErrBadFormat
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var w struct { // wireFile with the entries decoded incrementally
		Magic   string      `json:"magic"`
		Current string      `json:"current"`
		Entries wireEntries `json:"entries"`
	}
	if err := dec.Decode(&w); err != nil {
		if errors.Is(err, ErrBadFormat) {
			return nil, err // a bad entry, already described
		}
		return nil, ErrBadFormat
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, ErrBadFormat // trailing data
	}

	f := &File{Current: w.Current, Entries: w.Entries}
	if f.Entries == nil {
		f.Entries = []Entry{}
	}
	if f.Current != "" {
		if e := f.Find(f.Current); e == nil || e.Kind != KindEd25519 {
			return nil, fmt.Errorf("%w: current does not name a signing key", ErrBadFormat)
		}
	}
	return f, nil
}

func decodeEntry(w wireEntry) (Entry, error) {
	if err := ids.Valid(w.ID); err != nil {
		return Entry{}, err
	}
	p := kdf.Params{Algo: w.KDF.Algo, Mem: w.KDF.Mem, Time: w.KDF.Time, Par: w.KDF.Par, Salt: w.KDF.Salt}
	if err := p.Check(); err != nil {
		return Entry{}, err
	}
	if len(w.Nonce) != seal.NonceLen {
		return Entry{}, errors.New("bad nonce length")
	}
	if len(w.CT) < minCT {
		return Entry{}, errors.New("ciphertext too short")
	}
	created, err := time.Parse(time.RFC3339, w.Created)
	if err != nil {
		return Entry{}, errors.New("bad created time")
	}
	// Normalise to UTC (how it is written back) and keep it writable as RFC 3339.
	created = created.UTC()
	if y := created.Year(); y < 0 || y > 9999 {
		return Entry{}, errors.New("created time out of range")
	}
	switch w.Kind {
	case KindEd25519:
		pk, err := x509.ParsePKIXPublicKey(w.Pub)
		if err != nil {
			return Entry{}, errors.New("bad public key")
		}
		if _, ok := pk.(ed25519.PublicKey); !ok {
			return Entry{}, errors.New("public key is not ed25519")
		}
	case KindSecret:
		if len(w.Pub) != 0 {
			return Entry{}, errors.New("secret entry carries a public key")
		}
	default:
		return Entry{}, errors.New("unknown kind")
	}
	return Entry{ID: w.ID, Kind: w.Kind, Pub: w.Pub, KDF: p, Nonce: w.Nonce, CT: w.CT, Created: created}, nil
}

// Marshal encodes f in the canonical on-disk form. It refuses to produce bytes that
// Parse would reject, so no write path can leave an unreadable ring.
func Marshal(f *File) ([]byte, error) {
	b, err := marshal(f)
	if err != nil {
		return nil, err
	}
	if _, err := Parse(b); err != nil {
		return nil, fmt.Errorf("keystore: refusing to write an invalid ring: %w", err)
	}
	return b, nil
}

func marshal(f *File) ([]byte, error) {
	w := wireFile{Magic: Magic, Current: f.Current, Entries: make([]wireEntry, 0, len(f.Entries))}
	for _, e := range f.Entries {
		w.Entries = append(w.Entries, wireEntry{
			ID: e.ID, Kind: e.Kind, Pub: e.Pub,
			KDF:   wireKDF{Algo: e.KDF.Algo, Mem: e.KDF.Mem, Time: e.KDF.Time, Par: e.KDF.Par, Salt: e.KDF.Salt},
			Nonce: e.Nonce, CT: e.CT,
			Created: e.Created.UTC().Format(time.RFC3339),
		})
	}
	b, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Read loads and parses the ring at path.
func Read(path string) (*File, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, MaxSize+1))
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Create writes f as a new ring at path. It never replaces an existing file: the data
// is written to a temp file, synced, then hard-linked into place, which fails if path
// exists.
func Create(path string, f *File) error {
	b, err := Marshal(f)
	if err != nil {
		return err
	}
	tmp, err := writeTemp(path, b)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("keystore: %s already exists: %w", path, fs.ErrExist)
		}
		return err
	}
	return syncDir(filepath.Dir(path))
}

// Update applies fn to a fresh read of the ring under the exclusive lock and writes the
// result durably. If fn returns an error nothing is written. It returns the ring as
// written.
//
// A symlinked path is resolved first, so the write lands in the real ring (not over the
// link) and every spelling of the same ring shares one lock.
func Update(path string, fn func(*File) error) (*File, error) {
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	release, err := Lock(path)
	if err != nil {
		return nil, err
	}
	defer release()
	f, err := Read(path)
	if err != nil {
		return nil, err
	}
	if err := fn(f); err != nil {
		return nil, err
	}
	if err := Save(path, f); err != nil {
		return nil, err
	}
	return f, nil
}

// hook, when set by tests, is called after each write stage; a non-nil return aborts
// Save at that point, simulating a crash.
var hook func(stage string) error

func step(stage string) error {
	if hook != nil {
		return hook(stage)
	}
	return nil
}

// Save atomically replaces the ring at path with f. Callers must hold the lock; use
// Update.
func Save(path string, f *File) error {
	b, err := Marshal(f)
	if err != nil {
		return err
	}
	tmp, err := writeTemp(path, b)
	if err != nil {
		return err
	}
	defer os.Remove(tmp) // no-op once the rename succeeds
	if err := step("synced"); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if err := step("renamed"); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// writeTemp writes b to a new 0600 temp file beside path and fsyncs it. CreateTemp is
// O_EXCL with a random name, so a pre-planted file or symlink cannot be reused, and the
// mode is set on the descriptor before any byte is written.
func writeTemp(path string, b []byte) (string, error) {
	fh, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return "", err
	}
	name := fh.Name()
	fail := func(err error) (string, error) {
		fh.Close()
		os.Remove(name)
		return "", err
	}
	if err := fh.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := fh.Write(b); err != nil {
		return fail(err)
	}
	if err := step("written"); err != nil {
		return fail(err)
	}
	if err := fh.Sync(); err != nil {
		return fail(err)
	}
	if err := fh.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Lock takes the exclusive advisory lock for the ring at path (a sidecar file
// path+".lock", mode 0600, never followed if it is a symlink). It retries until
// LockTimeout, then returns ErrLocked.
func Lock(path string) (release func(), err error) {
	fh, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(LockTimeout)
	for {
		err := syscall.Flock(int(fh.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			fh.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			fh.Close()
			return nil, ErrLocked
		}
		time.Sleep(10 * time.Millisecond)
	}
	return func() {
		syscall.Flock(int(fh.Fd()), syscall.LOCK_UN)
		fh.Close()
	}, nil
}
