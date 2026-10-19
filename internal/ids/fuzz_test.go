package ids

import (
	"regexp"
	"strings"
	"testing"
)

// spec is the rule in the package doc, as an independent implementation.
var spec = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// FuzzValid is a differential test of Valid against the regexp: they must agree on
// every string, including embedded NULs, newlines (Go's $ is end of text, not end of
// line), invalid UTF-8 and the length boundary.
func FuzzValid(f *testing.F) {
	for _, s := range []string{
		"a", "Z", "0", "2026-prod", "zone.owner_b", "golden-ed25519",
		"", "-lead", ".lead", "_lead", "has space", "nul\x00byte", "new\nline", "trail\n", "a\n",
		"slash/x", "back\\x", "colon:x", "\x1b[31mred", "é", "tab\tx", "a\xff", "\xff",
		strings.Repeat("k", MaxLen-1), strings.Repeat("k", MaxLen), strings.Repeat("k", MaxLen+1),
		"a" + strings.Repeat(".", MaxLen-1), "a" + strings.Repeat("-", MaxLen),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, id string) {
		if got, want := Valid(id) == nil, spec.MatchString(id); got != want {
			t.Fatalf("Valid(%q) accepted=%v, regexp accepted=%v", id, got, want)
		}
	})
}
