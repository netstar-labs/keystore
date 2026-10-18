package agent

import (
	"encoding/binary"
	"errors"
	"io"
)

// Wire protocol. Every message, both directions, is one frame:
//
//	[b0:1][len:4 big-endian][payload:len]    len ≤ MaxPayload
//
// Request b0 is the operation; reply b0 is a status.
const (
	OpPublic byte = 'P' // reply payload: the 32-byte Ed25519 public key
	OpSign   byte = 'S' // reply payload: the 64-byte signature over the request payload

	StatusOK  byte = 0
	StatusErr byte = 1 // reply payload: a short error message

	// MaxPayload bounds any frame's payload: 1 MiB.
	MaxPayload = 1 << 20
)

// ErrTooLarge reports a frame whose length exceeds MaxPayload.
var ErrTooLarge = errors.New("keystore agent: frame exceeds 1 MiB")

func readFrame(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > MaxPayload {
		return 0, nil, ErrTooLarge
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	return hdr[0], p, nil
}

func writeFrame(w io.Writer, b0 byte, p []byte) error {
	if len(p) > MaxPayload {
		return ErrTooLarge
	}
	buf := make([]byte, 5, 5+len(p))
	buf[0] = b0
	binary.BigEndian.PutUint32(buf[1:], uint32(len(p)))
	_, err := w.Write(append(buf, p...))
	return err
}
