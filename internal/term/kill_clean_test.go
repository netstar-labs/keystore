package term

import "testing"

// Clean replaces each offending rune with one space: the length of what the operator sees
// is preserved and nothing is silently dropped, so a name cannot be made to read as a
// different one by deleting characters out of it. (Bytes that are not UTF-8 come out as
// U+FFFD, the replacement character: printable, and one per bad byte.)
func TestCleanReplacesEachOffendingRuneWithASpace(t *testing.T) {
	r := func(cp rune) string { return string(cp) } // spelled numerically: no raw bidi characters in this source
	for _, c := range []struct{ in, want string }{
		{"a\x1bb", "a b"},
		{"a\rb", "a b"},
		{"a\x00b", "a b"},
		{"a\x7fb", "a b"},
		{"a" + r(0x9b) + "b", "a b"},
		{"a" + r(0x202e) + "b", "a b"},
		{"a" + r(0x2066) + "b", "a b"},
		{"a" + r(0x2028) + "b" + r(0x2029) + "c", "a b c"},
		{"\x1b[31mred\x1b[0m", " [31mred [0m"},
		{"tab\there", "tab here"},
		{"line\nbreak", "line break"},
		{"ok name.txt", "ok name.txt"},
		// Spaces other than U+0020 are not printable in IsPrint's sense and are replaced: a
		// name must not be able to pose as another with a look-alike space.
		{"a" + r(0xa0) + "b", "a b"},
		{"a" + r(0x2003) + "b", "a b"},
		{"a" + r(0x3000) + "b", "a b"},
		{"\xff", r(0xfffd)},
		{"a\xc0\xafb", "a" + r(0xfffd) + r(0xfffd) + "b"},
	} {
		if got := Clean(c.in); got != c.want {
			t.Errorf("Clean(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
