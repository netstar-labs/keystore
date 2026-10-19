package agent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"runtime"
	"testing"
)

// FuzzFrameRoundTrip: writeFrame then readFrame returns the same (status, payload) and
// consumes exactly the frame; payloads past MaxPayload are refused on both sides; and
// readFrame allocates no more than the length the header declares (and nothing for a
// header that declares too much), however much of the body is actually there.
//
// boundary < 8 stretches the payload to MaxPayload-3 .. MaxPayload+4 so the limit is
// exercised from both sides; cut truncates the encoded frame; decl, when non-zero,
// overwrites the declared length.
func FuzzFrameRoundTrip(f *testing.F) {
	f.Add(OpSign, []byte("message"), uint8(255), uint32(0), uint32(0))
	f.Add(StatusOK, []byte(nil), uint8(255), uint32(0), uint32(0))
	f.Add(StatusErr, []byte("a short error"), uint8(255), uint32(0), uint32(0))
	f.Add(byte(0xff), bytes.Repeat([]byte{0xa5}, 300), uint8(255), uint32(0), uint32(0))
	f.Add(OpPublic, []byte("x"), uint8(3), uint32(0), uint32(0))             // exactly MaxPayload
	f.Add(OpPublic, []byte("x"), uint8(4), uint32(0), uint32(0))             // MaxPayload+1
	f.Add(OpSign, []byte("body"), uint8(255), uint32(0), uint32(0xffffffff)) // huge declared length
	f.Add(OpSign, []byte("body"), uint8(255), uint32(0), uint32(MaxPayload)) // declared max, tiny body
	f.Add(OpSign, []byte("body"), uint8(255), uint32(6), uint32(0))          // cut mid-payload
	f.Fuzz(func(t *testing.T, b0 byte, payload []byte, boundary uint8, cut, decl uint32) {
		if boundary < 8 {
			n := MaxPayload - 3 + int(boundary)
			seed := append([]byte{0}, payload...)
			payload = make([]byte, n)
			for i := range payload {
				payload[i] = seed[i%len(seed)]
			}
		}

		var buf bytes.Buffer
		err := writeFrame(&buf, b0, payload)
		if len(payload) > MaxPayload {
			if !errors.Is(err, ErrTooLarge) || buf.Len() != 0 {
				t.Fatalf("writeFrame of %d bytes: err=%v, wrote %d", len(payload), err, buf.Len())
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		enc := buf.Bytes()
		if len(enc) != 5+len(payload) || enc[0] != b0 || int(binary.BigEndian.Uint32(enc[1:5])) != len(payload) {
			t.Fatalf("malformed frame: %d bytes for %d-byte payload, header % x", len(enc), len(payload), enc[:5])
		}

		// Clean round trip, with trailing bytes that must be left unread.
		r := bytes.NewReader(append(bytes.Clone(enc), "next"...))
		op, p, err := readFrame(r)
		if err != nil || op != b0 || !bytes.Equal(p, payload) || r.Len() != 4 {
			t.Fatalf("round trip: op=%#x err=%v equal=%v unread=%d", op, err, bytes.Equal(p, payload), r.Len())
		}

		// Hostile variant: a (possibly lying) declared length over a possibly truncated body.
		bad := bytes.Clone(enc)
		if decl != 0 {
			binary.BigEndian.PutUint32(bad[1:5], decl)
		}
		if cut != 0 {
			bad = bad[:int(cut)%(len(bad)+1)]
		}
		declared := uint64(binary.BigEndian.Uint32(append(bytes.Clone(bad), 0, 0, 0, 0, 0)[1:5]))
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, p, err = readFrame(bytes.NewReader(bad))
		runtime.ReadMemStats(&after)
		const slack = 64 << 10 // reader, MemStats and test bookkeeping
		// readFrame grows its buffer with the bytes that arrive (io.ReadAll doubles, so up
		// to ~4.25x what is present), so the oracle tracks the bytes actually present, not
		// the claim; see frame_alloc_test.go.
		limit := 5 * min(declared, uint64(max(len(bad)-5, 0)))
		if declared > MaxPayload {
			limit = 0
		}
		if grew := after.TotalAlloc - before.TotalAlloc; grew > limit+slack {
			t.Fatalf("readFrame allocated %d bytes for a header declaring %d (limit %d + %d)", grew, declared, limit, slack)
		}
		switch {
		case len(bad) < 5, declared > MaxPayload, uint64(len(bad)-5) < declared:
			if err == nil {
				t.Fatalf("accepted a bad frame (%d bytes, declared %d)", len(bad), declared)
			}
		case err != nil || uint64(len(p)) != declared:
			t.Fatalf("refused a good frame: err=%v len(p)=%d declared=%d", err, len(p), declared)
		}
	})
}
