package agent

import (
	"bytes"
	"testing"
)

func FuzzReadFrame(f *testing.F) {
	var ok bytes.Buffer
	writeFrame(&ok, OpSign, []byte("message"))
	f.Add(ok.Bytes())
	f.Add([]byte{OpPublic, 0, 0, 0, 0})
	f.Add([]byte{OpSign, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{OpSign, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		op, p, err := readFrame(bytes.NewReader(b))
		if err != nil {
			return
		}
		if len(p) > MaxPayload {
			t.Fatalf("accepted %d-byte payload", len(p))
		}
		var again bytes.Buffer
		if err := writeFrame(&again, op, p); err != nil || !bytes.HasPrefix(b, again.Bytes()) {
			t.Fatalf("frame does not round-trip")
		}
	})
}
