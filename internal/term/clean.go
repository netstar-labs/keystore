package term

import (
	"io"
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

// Writer returns a writer that Cleans what is written to w, keeping newlines and tabs.
// It is for output the tool does not format itself, such as the flag package's errors,
// which echo an unknown flag name verbatim.
func Writer(w io.Writer) io.Writer { return cleanWriter{w} }

type cleanWriter struct{ w io.Writer }

func (c cleanWriter) Write(p []byte) (int, error) {
	out := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		return scrub(r)
	}, string(p))
	if _, err := io.WriteString(c.w, out); err != nil {
		return 0, err
	}
	return len(p), nil
}
