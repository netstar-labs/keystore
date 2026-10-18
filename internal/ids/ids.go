// Package ids defines which strings are valid keystore entry ids.
//
// An id is 1–64 bytes of [A-Za-z0-9._-] starting with an ASCII letter or digit. The
// restriction keeps ids safe to print, to use in file names and shell arguments, and
// free of the separators that would make associated-data encodings ambiguous.
package ids

import "errors"

// MaxLen is the longest permitted id, in bytes.
const MaxLen = 64

// ErrBadID reports an id outside the permitted alphabet or length.
var ErrBadID = errors.New("keystore: invalid entry id (1-64 chars of A-Z a-z 0-9 . _ -, starting alphanumeric)")

// Valid returns nil if id is a permitted entry id, else ErrBadID.
func Valid(id string) error {
	if len(id) == 0 || len(id) > MaxLen {
		return ErrBadID
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case (c == '.' || c == '_' || c == '-') && i > 0:
		default:
			return ErrBadID
		}
	}
	return nil
}
