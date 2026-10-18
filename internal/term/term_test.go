package term

import (
	"os"
	"testing"
)

func TestIsTerminalOnRegularFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if IsTerminal(f.Fd()) {
		t.Fatal("a regular file reported as a terminal")
	}
}

func TestReadLine(t *testing.T) {
	r, w, _ := os.Pipe()
	w.WriteString("secret\r\nnext")
	w.Close()
	got, err := readLine(r)
	if err != nil || string(got) != "secret" {
		t.Fatalf("readLine = %q, %v", got, err)
	}
	rest, _ := readLine(r)
	if string(rest) != "next" {
		t.Fatalf("readLine consumed past the newline: %q", rest)
	}
}

func TestReadLineTooLong(t *testing.T) {
	r, w, _ := os.Pipe()
	go func() {
		w.Write(make([]byte, MaxLen+10))
		w.Close()
	}()
	if _, err := readLine(r); err == nil {
		t.Fatal("over-long line accepted")
	}
}
