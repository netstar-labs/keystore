package keystore

import "testing"

// Signer must return a nil crypto.Signer with its error, not an interface wrapping a nil
// ed25519.PrivateKey.
func TestSignerReturnsNilOnError(t *testing.T) {
	k, _ := newRing(t)
	if _, err := k.Add("a", pass); err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() (any, error){
		"wrong passphrase": func() (any, error) { s, err := k.Signer("a", []byte("wrong")); return s, err },
		"no such key":      func() (any, error) { s, err := k.Signer("zzz", pass); return s, err },
	} {
		s, err := call()
		if err == nil || s != nil {
			t.Errorf("%s: signer %#v, err %v; want a nil signer and an error", name, s, err)
		}
	}
}
