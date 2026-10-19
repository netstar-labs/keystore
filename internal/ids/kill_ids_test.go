package ids

import (
	"errors"
	"strings"
	"testing"
)

// Each class boundary and the separator rule, one character at a time.
func TestValidBoundaryCharacters(t *testing.T) {
	for _, id := range []string{"a", "z", "A", "Z", "0", "9", "aa", "aA", "az", "aZ", "a0", "a9", "a.", "a_", "a-", "A.b", "9-9"} {
		if err := Valid(id); err != nil {
			t.Errorf("Valid(%q) = %v, want nil", id, err)
		}
	}
	for _, id := range []string{"`", "{", "@", "[", "/", ":", " ", "a b", "a/", "a:", "a@", "a[", "a`", "a{", "a\x7f", ".a", "-a", "_a"} {
		if err := Valid(id); !errors.Is(err, ErrBadID) {
			t.Errorf("Valid(%q) = %v, want ErrBadID", id, err)
		}
	}
}

func TestValidLengthBoundary(t *testing.T) {
	for n, ok := range map[int]bool{0: false, 1: true, 63: true, 64: true, 65: false} {
		err := Valid(strings.Repeat("a", n))
		if ok && err != nil {
			t.Errorf("%d bytes: %v", n, err)
		}
		if !ok && !errors.Is(err, ErrBadID) {
			t.Errorf("%d bytes: %v, want ErrBadID", n, err)
		}
	}
}
