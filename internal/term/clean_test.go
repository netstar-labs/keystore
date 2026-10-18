package term

import (
	"strings"
	"testing"
	"unicode"
)

func TestCleanKeepsReadableNamesAndNeutralisesTheRest(t *testing.T) {
	for _, keep := range []string{"résumé.pdf", "résumé.pdf", "文件.sig", "🔑.pem", "שלום.txt", "مرحبا.txt", "plain name-1.0_x"} {
		if got := Clean(keep); got != keep {
			t.Errorf("Clean(%q) = %q, want it unchanged", keep, got)
		}
	}
	for name, in := range map[string]string{
		"ESC sequence": "a\x1b[31mb\x1b]0;t\x07c",
		"CR":           "a\rb",
		"DEL and C1":   "a\x7fb\u009bc",
		"bidi":         "a\u202eb\u2066c",
		"separators":   "a\u2028b\u2029c",
		"NUL":          "a\x00b",
		"invalid byte": "a\xffb\xc0\xaf",
	} {
		got := Clean(in)
		for _, r := range got {
			if !unicode.IsPrint(r) {
				t.Errorf("%s: Clean(%q) = %q still holds %U", name, in, got, r)
			}
		}
		if !strings.HasPrefix(got, "a") {
			t.Errorf("%s: Clean(%q) = %q lost the readable part", name, in, got)
		}
	}
}
