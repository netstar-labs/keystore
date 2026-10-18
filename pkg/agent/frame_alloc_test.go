package agent

import (
	"bytes"
	"io"
	"runtime"
	"testing"
)

// A peer that claims a 1 MiB body and then stalls must not make us hold 1 MiB: memory
// follows the bytes that actually arrived, so many stalled connections stay cheap.
func TestReadFrameShortBodyAllocatesLittle(t *testing.T) {
	hdr := []byte{OpSign, 0x00, 0x10, 0x00, 0x00} // claims MaxPayload
	const runs = 20
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range runs {
		_, _, err := readFrame(io.MultiReader(bytes.NewReader(hdr), bytes.NewReader([]byte("abc"))))
		if err != io.ErrUnexpectedEOF {
			t.Fatalf("short body: err = %v, want io.ErrUnexpectedEOF", err)
		}
	}
	runtime.ReadMemStats(&after)
	if per := (after.TotalAlloc - before.TotalAlloc) / runs; per > 64<<10 {
		t.Fatalf("a 1 MiB claim with 3 bytes sent allocated %d bytes per call, want < 64 KiB", per)
	}
}

// The boundary frame still round-trips, and a body one byte short is still an error.
func TestReadFrameMaxPayloadExact(t *testing.T) {
	body := bytes.Repeat([]byte{0xa5}, MaxPayload)
	var buf bytes.Buffer
	if err := writeFrame(&buf, OpSign, body); err != nil {
		t.Fatal(err)
	}
	full := buf.Bytes()
	if op, p, err := readFrame(bytes.NewReader(full)); err != nil || op != OpSign || !bytes.Equal(p, body) {
		t.Fatalf("1 MiB frame: op=%c len=%d err=%v", op, len(p), err)
	}
	if _, _, err := readFrame(bytes.NewReader(full[:len(full)-1])); err != io.ErrUnexpectedEOF {
		t.Fatalf("1 MiB frame minus a byte: err = %v, want io.ErrUnexpectedEOF", err)
	}
}
