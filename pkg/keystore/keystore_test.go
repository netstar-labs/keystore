package keystore

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/netstar-labs/keystore/internal/kdf"
)

var pass = []byte("correct horse battery")

func TestMain(m *testing.M) {
	// Minimum accepted cost keeps the suite fast; the golden test opens a ring written
	// at the production cost, so the default parameters are still exercised.
	kdf.Default = kdf.Cost{Mem: kdf.MinMem, Time: 1, Par: 1}
	if os.Getenv("KEYSTORE_TEST_CHILD") == "add" {
		childAdd()
		return
	}
	os.Exit(m.Run())
}

func newRing(t *testing.T) (*Keystore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "r.ks")
	k, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	return k, path
}

func TestAddSignVerify(t *testing.T) {
	k, path := newRing(t)
	pub, err := k.Add("a", pass)
	if err != nil {
		t.Fatal(err)
	}
	if k.CurrentID() != "a" {
		t.Fatalf("first key not current: %q", k.CurrentID())
	}
	// Reopen from disk: the snapshot must not be what makes this work.
	k2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := k2.Signer("", pass)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign(nil, []byte("msg"), &ed25519.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, []byte("msg"), sig) {
		t.Fatal("signature does not verify under the returned public key")
	}
	got, err := k2.Public("a")
	if err != nil || !got.Equal(pub) {
		t.Fatalf("Public = %x, %v", got, err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("ring mode %v, want 0600", st.Mode().Perm())
	}
}

func TestWrongPassphrase(t *testing.T) {
	k, _ := newRing(t)
	k.Add("a", pass)
	if _, err := k.Signer("a", []byte("not the passphrase")); !errors.Is(err, ErrBadPass) {
		t.Fatalf("Signer with wrong passphrase = %v, want ErrBadPass", err)
	}
}

func TestImportExportRoundTrip(t *testing.T) {
	k, _ := newRing(t)
	_, priv, _ := ed25519.GenerateKey(nil)
	if err := k.Import("imp", priv, pass); err != nil {
		t.Fatal(err)
	}
	out, err := k.ExportPrivate("imp", pass)
	if err != nil || !out.Equal(priv) {
		t.Fatalf("ExportPrivate mismatch: %v", err)
	}
	pemB, _ := MarshalPrivateKeyPEM(priv)
	back, err := ParsePrivateKeyPEM(pemB)
	if err != nil || !back.Equal(priv) {
		t.Fatalf("private PEM round trip: %v", err)
	}
	pubPEM, _ := MarshalPublicKeyPEM(priv.Public().(ed25519.PublicKey))
	pub, err := ParsePublicKeyPEM(pubPEM)
	if err != nil || !pub.Equal(priv.Public()) {
		t.Fatalf("public PEM round trip: %v", err)
	}
	if _, err := ParsePublicKeyPEM(append(pubPEM, pubPEM...)); err == nil {
		t.Fatal("two PEM blocks accepted")
	}
	if _, err := ParsePrivateKeyPEM(pubPEM); err == nil {
		t.Fatal("public PEM accepted as private")
	}
}

func TestPassphraseInvariant(t *testing.T) {
	k, path := newRing(t)
	k.Add("a", pass)
	before, _ := os.ReadFile(path)
	if _, err := k.Add("b", []byte("a different passphrase")); !errors.Is(err, ErrPassphraseMismatch) {
		t.Fatalf("Add with other passphrase = %v, want ErrPassphraseMismatch", err)
	}
	_, priv, _ := ed25519.GenerateKey(nil)
	if err := k.Import("c", priv, []byte("a different passphrase")); !errors.Is(err, ErrPassphraseMismatch) {
		t.Fatalf("Import with other passphrase = %v, want ErrPassphraseMismatch", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("ring changed after a refused add")
	}
}

func TestIDsAndExistence(t *testing.T) {
	k, _ := newRing(t)
	if _, err := k.Add("-bad", pass); !errors.Is(err, ErrBadID) {
		t.Fatalf("bad id: %v", err)
	}
	k.Add("a", pass)
	if _, err := k.Add("a", pass); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate id: %v", err)
	}
	if _, err := k.Signer("nope", pass); !errors.Is(err, ErrNoKey) {
		t.Fatalf("missing id: %v", err)
	}
	if err := k.Use("nope"); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Use missing: %v", err)
	}
	if _, err := Create(k.Path()); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("Create over existing: %v", err)
	}
}

func TestEmptyRingHasNoCurrent(t *testing.T) {
	k, _ := newRing(t)
	if _, err := k.Public(""); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Public on empty ring = %v", err)
	}
}

func TestUseAndRemove(t *testing.T) {
	k, _ := newRing(t)
	k.Add("a", pass)
	k.Add("b", pass)
	k.Add("c", pass)
	if err := k.Use("b"); err != nil || k.CurrentID() != "b" {
		t.Fatalf("Use: %v, current %q", err, k.CurrentID())
	}
	if err := k.Remove("b", false); err != nil {
		t.Fatal(err)
	}
	if k.CurrentID() != "a" {
		t.Fatalf("current after removing it = %q, want first remaining signing key", k.CurrentID())
	}
	k.Remove("c", false)
	if err := k.Remove("a", false); !errors.Is(err, ErrLastSigningKey) {
		t.Fatalf("removing last key without force = %v", err)
	}
	if err := k.Remove("a", true); err != nil || k.CurrentID() != "" || len(k.List()) != 0 {
		t.Fatalf("force remove: %v, current %q, %d left", err, k.CurrentID(), len(k.List()))
	}
	if err := k.Remove("a", true); !errors.Is(err, ErrNoKey) {
		t.Fatalf("remove missing: %v", err)
	}
}

func TestListCarriesNoSecrets(t *testing.T) {
	k, _ := newRing(t)
	pub, _ := k.Add("a", pass)
	l := k.List()
	if len(l) != 1 || !l[0].Current || l[0].Kind != KindEd25519 || !l[0].Public.Equal(pub) {
		t.Fatalf("List = %+v", l)
	}
	if l[0].Fingerprint != Fingerprint(pub) || len(l[0].Fingerprint) != len("SHA256:")+43 {
		t.Fatalf("fingerprint %q", l[0].Fingerprint)
	}
}

func TestOpenOrCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.ks")
	k, err := OpenOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	k.Add("a", pass)
	k2, err := OpenOrCreate(path)
	if err != nil || k2.CurrentID() != "a" {
		t.Fatalf("OpenOrCreate on existing: %v, current %q", err, k2.CurrentID())
	}
}

// Tamper matrix: a modification of any field must make Open or Signer fail, and nothing
// may panic.
func TestTamperMatrix(t *testing.T) {
	flipB64 := func(v any) any {
		b, _ := base64.StdEncoding.DecodeString(v.(string))
		b[len(b)/2] ^= 0x01
		return base64.StdEncoding.EncodeToString(b)
	}
	cases := map[string]func(ring, e map[string]any){
		"magic":     func(r, _ map[string]any) { r["magic"] = "keystore/v0" },
		"id":        func(r, e map[string]any) { e["id"] = "z"; r["current"] = "z" },
		"kind":      func(_, e map[string]any) { e["kind"] = "secret" },
		"pub":       func(_, e map[string]any) { e["pub"] = flipB64(e["pub"]) },
		"kdf.algo":  func(_, e map[string]any) { kdfOf(e)["algo"] = "argon2i" },
		"kdf.mem":   func(_, e map[string]any) { kdfOf(e)["mem"] = kdfOf(e)["mem"].(float64) + 1 },
		"kdf.time":  func(_, e map[string]any) { kdfOf(e)["time"] = kdfOf(e)["time"].(float64) + 1 },
		"kdf.par":   func(_, e map[string]any) { kdfOf(e)["par"] = kdfOf(e)["par"].(float64) + 1 },
		"kdf.salt":  func(_, e map[string]any) { kdfOf(e)["salt"] = flipB64(kdfOf(e)["salt"]) },
		"nonce":     func(_, e map[string]any) { e["nonce"] = flipB64(e["nonce"]) },
		"ct":        func(_, e map[string]any) { e["ct"] = flipB64(e["ct"]) },
		"ct.trunc":  func(_, e map[string]any) { e["ct"] = e["ct"].(string)[:24] },
		"created":   func(_, e map[string]any) { e["created"] = "2020-01-01T00:00:00Z" }, // metadata only: must still open
		"swap.pubs": nil,
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			k, path := newRing(t)
			k.Add("a", pass)
			k.Add("b", pass)
			raw, _ := os.ReadFile(path)
			var ring map[string]any
			json.Unmarshal(raw, &ring)
			ents := ring["entries"].([]any)
			e := ents[0].(map[string]any)
			if mut == nil { // move b's public key onto a
				e["pub"] = ents[1].(map[string]any)["pub"]
			} else {
				mut(ring, e)
			}
			out, _ := json.Marshal(ring)
			os.WriteFile(path, out, 0o600)

			k2, err := Open(path)
			if err == nil {
				id := e["id"].(string)
				_, err = k2.Signer(id, pass)
			}
			if name == "created" {
				if err != nil {
					t.Fatalf("created is unauthenticated metadata, but opening failed: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("tampered %s: ring opened and unlocked", name)
			}
		})
	}
}

func kdfOf(e map[string]any) map[string]any { return e["kdf"].(map[string]any) }

// N goroutines and N child processes add distinct ids to one ring; all must survive.
func TestConcurrentAddsGoroutinesAndProcesses(t *testing.T) {
	_, path := newRing(t)
	const n = 6
	var wg sync.WaitGroup
	errs := make(chan error, 2*n)
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			k, err := Open(path)
			if err == nil {
				_, err = k.Add(fmt.Sprintf("g%d", i), pass)
			}
			errs <- err
		}()
		go func() {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^$")
			cmd.Env = append(os.Environ(), "KEYSTORE_TEST_CHILD=add",
				"KEYSTORE_TEST_RING="+path, fmt.Sprintf("KEYSTORE_TEST_ID=p%d", i))
			out, err := cmd.CombinedOutput()
			if err != nil {
				err = fmt.Errorf("child: %v: %s", err, out)
			}
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
	k, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(k.List()); got != 2*n {
		t.Fatalf("%d entries after %d concurrent adds", got, 2*n)
	}
}

func childAdd() {
	k, err := Open(os.Getenv("KEYSTORE_TEST_RING"))
	if err == nil {
		_, err = k.Add(os.Getenv("KEYSTORE_TEST_ID"), pass)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}
