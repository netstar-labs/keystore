package keystore

import (
	"slices"
	"testing"
)

func entryIDs(k *Keystore) []string {
	var out []string
	for _, e := range k.List() {
		out = append(out, e.ID)
	}
	return out
}

// Remove deletes exactly the named entry, wherever it sits (first, middle, last), and
// leaves the others in order.
func TestRemoveDeletesExactlyOneEntry(t *testing.T) {
	for _, c := range []struct {
		rm   string
		want []string
	}{
		{"a", []string{"b", "c"}},
		{"b", []string{"a", "c"}},
		{"c", []string{"a", "b"}},
	} {
		pw := []byte("some passphrase here")
		k, path := ringOf(t, "a", signingEntry(t, "a", pw), signingEntry(t, "b", pw), signingEntry(t, "c", pw))
		if err := k.Remove(c.rm, false); err != nil {
			t.Fatalf("Remove(%s): %v", c.rm, err)
		}
		if got := entryIDs(k); !slices.Equal(got, c.want) {
			t.Errorf("after Remove(%s): %v, want %v", c.rm, got, c.want)
		}
		k2, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := entryIDs(k2); !slices.Equal(got, c.want) {
			t.Errorf("after Remove(%s), reopened: %v, want %v", c.rm, got, c.want)
		}
	}
}
