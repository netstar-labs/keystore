package term

import (
	"strings"
	"unicode"
)

// Clean replaces every non-printable rune with a space: control characters including
// ESC, CR, DEL and C1, line and paragraph separators, bidi overrides, and invalid UTF-8.
// Anything a command prints that it did not produce itself (a file name an operator's
// script took from an archive or an upload, an OS error that quotes one) goes through it,
// so an escape sequence or a carriage return cannot act on the terminal or forge a line
// of the tool's own output.
func Clean(s string) string { return strings.Map(scrub, s) }

func scrub(r rune) rune {
	if unicode.IsPrint(r) {
		return r
	}
	return ' '
}
