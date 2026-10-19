package ringfile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The ring is owner-only under any umask. os.CreateTemp asks for 0600 but the umask can
// only narrow it, so a hostile or odd umask (0277 leaves 0400) must not leave the ring
// read-only to its owner: the explicit chmod on the descriptor sets exactly 0600.
func TestRingModeIs0600UnderAnyUmask(t *testing.T) {
	for _, umask := range []int{0o000, 0o077, 0o277, 0o377} {
		dir := t.TempDir() // made before the umask changes
		path := filepath.Join(dir, "r.ks")
		old := syscall.Umask(umask)
		err := Create(path, sample(t))
		var err2 error
		if err == nil {
			_, err2 = Update(path, func(*File) error { return nil })
		}
		syscall.Umask(old)
		if err != nil || err2 != nil {
			t.Fatalf("umask %04o: Create %v, Update %v", umask, err, err2)
		}
		st, _ := os.Stat(path)
		if st.Mode().Perm() != 0o600 {
			t.Errorf("umask %04o: ring mode %04o, want 0600", umask, st.Mode().Perm())
		}
	}
}

// Save replaces the ring by rename, never by rewriting it in place: the file that was
// open before the write still holds the complete old ring afterwards, and the path now
// names a different inode.
func TestSaveReplacesTheFileInsteadOfRewritingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.ks")
	if err := Create(path, sample(t)); err != nil {
		t.Fatal(err)
	}
	oldB, _ := os.ReadFile(path)
	old, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	ino := func(fi os.FileInfo) uint64 { return fi.Sys().(*syscall.Stat_t).Ino }
	before, _ := old.Stat()
	if _, err := Update(path, func(f *File) error { f.Entries = f.Entries[:1]; return nil }); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if ino(before) == ino(after) {
		t.Fatal("the ring was rewritten in place (same inode)")
	}
	still := make([]byte, len(oldB)+16)
	n, _ := old.ReadAt(still, 0)
	if string(still[:n]) != string(oldB) {
		t.Fatal("the previous file's contents were modified by the write")
	}
}
