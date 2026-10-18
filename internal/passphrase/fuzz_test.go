package passphrase

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// FuzzReadPassfile writes arbitrary bytes to a 0600 file and reads them back through
// readPassfile. Invariants: no panic; the cap is exact (the file as stored, newline
// included, is at most 4096 bytes, else an error); the result is never longer than
// 4096; and exactly one trailing LF and then one trailing CR are removed, the rest
// preserved byte for byte.
func FuzzReadPassfile(f *testing.F) {
	for _, s := range [][]byte{
		nil, []byte("\n"), []byte("\r\n"), []byte("\r"), []byte("\n\n"), []byte("\n\r"), []byte("a\r\r"), []byte("a\r\r\n"), []byte("a\n\n"), []byte("\r\n\r\n"),
		[]byte("correct horse battery staple"), []byte("correct horse battery staple\n"),
		[]byte("correct horse battery staple\r\n"), []byte("with\nnewline\ninside\n"),
		[]byte("é\u2028\x00\xff"),
		bytes.Repeat([]byte("a"), maxFile-1), bytes.Repeat([]byte("a"), maxFile),
		bytes.Repeat([]byte("a"), maxFile+1), bytes.Repeat([]byte("a"), maxFile+2),
		append(bytes.Repeat([]byte("a"), maxFile-1), '\n'), // 4096 stored bytes: accepted
		append(bytes.Repeat([]byte("a"), maxFile), '\n'),   // 4097 stored bytes: refused
		append(bytes.Repeat([]byte("a"), maxFile-2), "\r\n"...),
		append(bytes.Repeat([]byte("a"), maxFile-1), '\r'),
	} {
		f.Add(s)
	}
	path := filepath.Join(f.TempDir(), "passfile")
	f.Fuzz(func(t *testing.T, content []byte) {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		os.Chmod(path, 0o600) // WriteFile keeps the mode of an existing file; be explicit
		got, err := readPassfile(path)
		if len(content) > maxFile {
			if err == nil {
				t.Fatalf("a %d-byte passfile was accepted (cap %d)", len(content), maxFile)
			}
			return
		}
		if err != nil {
			t.Fatalf("a %d-byte passfile was refused: %v", len(content), err)
		}
		if len(got) > maxFile {
			t.Fatalf("result is %d bytes, over the cap", len(got))
		}
		want := content
		if n := len(want); n > 0 && want[n-1] == '\n' {
			want = want[:n-1]
		}
		if n := len(want); n > 0 && want[n-1] == '\r' {
			want = want[:n-1]
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("readPassfile(%q) = %q, want %q", content, got, want)
		}
	})
}
