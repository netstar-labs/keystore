package ids

import (
	"errors"
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	good := []string{"a", "Z", "0", "2026-prod", "zone.owner_b", strings.Repeat("k", MaxLen)}
	for _, id := range good {
		if err := Valid(id); err != nil {
			t.Errorf("Valid(%q) = %v, want nil", id, err)
		}
	}
	bad := []string{
		"", "-lead", ".lead", "_lead", strings.Repeat("k", MaxLen+1),
		"has space", "nul\x00byte", "new\nline", "slash/x", "back\\x", "colon:x",
		"\x1b[31mred", "é", "tab\tx",
	}
	for _, id := range bad {
		if err := Valid(id); !errors.Is(err, ErrBadID) {
			t.Errorf("Valid(%q) = %v, want ErrBadID", id, err)
		}
	}
}
