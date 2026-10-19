package agent

import (
	"path/filepath"
	"testing"

	"github.com/netstar-labs/keystore/pkg/keystore"
)

// A failed ResolveSigner must return a nil crypto.Signer, not an interface holding a nil
// *Client or nil key: a caller that tests the value instead of the error would otherwise
// carry on with a signer that panics on first use.
func TestResolveSignerReturnsNilSignerOnError(t *testing.T) {
	if s, err := ResolveSigner(filepath.Join(sockDir(t), "none.sock"), "", "", nil); err == nil || s != nil {
		t.Errorf("dead agent: signer %#v, err %v; want a nil signer and an error", s, err)
	}
	ring := filepath.Join(t.TempDir(), "r.ks")
	k, err := keystore.Create(ring)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Add("a", []byte("resolve nil test passphrase")); err != nil {
		t.Fatal(err)
	}
	wrong := func() ([]byte, error) { return []byte("not the passphrase"), nil }
	if s, err := ResolveSigner("", ring, "", wrong); err == nil || s != nil {
		t.Errorf("wrong passphrase: signer %#v, err %v; want a nil signer and an error", s, err)
	}
}
