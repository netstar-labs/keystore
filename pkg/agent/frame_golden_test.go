package agent

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Golden frames for the wire protocol. The expected bytes were written from
// docs/agent-protocol.md ("Framing", "Requests", "Replies"): b0, a 4-byte big-endian
// length, the payload. The signature came from OpenSSL 3.5 (`pkeyutl -sign -rawin`), not
// from Go, for the RFC 8032 test-1 key. The server tests below speak raw bytes on the
// socket, so they check the real handler and not just writeFrame against readFrame.

const wireBreak = "AGENT WIRE FORMAT CHANGED (%s). The protocol carries no version: an old client or agent will read these " +
	"bytes as the old shape and accept a wrong value (a length read from the wrong offset, a status taken as an op) " +
	"silently, or hang until the deadline. If the change is intended it needs a NEW operation byte, not a new shape for " +
	"P or S. Do not re-record this golden to make the test pass."

const (
	rfcSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	rfcPubHex  = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	// signature of "keystore golden" under the RFC 8032 test-1 key (OpenSSL 3.5.9).
	rfcSigHex = "8719127bb4a2ded6ff8e3455f9ded4db3649c11a196c79af44bb7e8159ef6111a3205492a10f2d5dd1fba38cb5c4b752d8cca3100ac3bb5187c96efe29d3e907"
)

func TestWriteFrameGolden(t *testing.T) {
	for _, c := range []struct {
		name string
		b0   byte
		p    []byte
		want string
	}{
		{"P request", OpPublic, nil, "5000000000"},
		{"S request", OpSign, []byte("keystore golden"), "530000000f6b657973746f726520676f6c64656e"},
		{"ok reply, 3 bytes", StatusOK, []byte{1, 2, 3}, "0000000003010203"},
		{"error reply", StatusErr, []byte("unknown operation"), "0100000011756e6b6e6f776e206f7065726174696f6e"},
	} {
		var b bytes.Buffer
		if err := writeFrame(&b, c.b0, c.p); err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(b.Bytes()); got != c.want {
			t.Errorf(wireBreak+"\n got  %s\n want %s", c.name, got, c.want)
		}
	}
	// The boundary: exactly 1 MiB is framed with length 0x00100000; one more is refused.
	var b bytes.Buffer
	if err := writeFrame(&b, OpSign, make([]byte, 1<<20)); err != nil || hex.EncodeToString(b.Bytes()[:5]) != "5300100000" {
		t.Errorf(wireBreak, "1 MiB header "+hex.EncodeToString(b.Bytes()[:5]))
	}
	if err := writeFrame(io.Discard, OpSign, make([]byte, 1<<20+1)); err != ErrTooLarge {
		t.Errorf("writeFrame(1 MiB + 1) = %v, want ErrTooLarge", err)
	}
	// readFrame: the same bytes parse back, and a length over the limit is ErrTooLarge
	// from the header alone, before any payload is read.
	if op, p, err := readFrame(bytes.NewReader([]byte{0x53, 0, 0, 0, 3, 'a', 'b', 'c'})); err != nil || op != OpSign || string(p) != "abc" {
		t.Errorf("readFrame = %c %q %v", op, p, err)
	}
	if _, _, err := readFrame(bytes.NewReader([]byte{0x53, 0x00, 0x10, 0x00, 0x01})); err != ErrTooLarge {
		t.Errorf("readFrame(1 MiB + 1 header) = %v, want ErrTooLarge", err)
	}
}

// rawExchange sends req on a fresh connection and reads the reply frame's header and
// payload as raw bytes.
func rawExchange(t *testing.T, sock string, req []byte) (reply []byte, conn net.Conn) {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatalf("reading reply header: %v", err)
	}
	n := int(hdr[1])<<24 | int(hdr[2])<<16 | int(hdr[3])<<8 | int(hdr[4])
	p := make([]byte, n)
	if _, err := io.ReadFull(c, p); err != nil {
		t.Fatalf("reading %d-byte reply payload: %v", n, err)
	}
	return append(hdr, p...), c
}

// The lock file's name is part of the cross-version protocol: two agent builds exclude
// each other only if both lock the same path. A build that renamed it would let an old
// and a new agent both "own" one socket path, each unlinking the other's socket.
func TestAgentLockFileName(t *testing.T) {
	sock := filepath.Join(sockDir(t), "agent.sock")
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if st, err := os.Stat(sock + ".lock"); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("lock file %s.lock: %v, %v (docs/agent-protocol.md: exclusive flock on <socket>.lock)", sock, st, err)
	}
}

func TestServerWireGolden(t *testing.T) {
	seed, _ := hex.DecodeString(rfcSeedHex)
	srv, err := NewServer(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(sockDir(t), "agent.sock")
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	hexOf := func(b []byte) string { return hex.EncodeToString(b) }
	for _, c := range []struct {
		name, req, want string
	}{
		{"P", "5000000000", "00" + "00000020" + rfcPubHex},
		// "any payload sent is ignored" (docs/agent-protocol.md, Requests).
		{"P with payload", "500000000401020304", "00" + "00000020" + rfcPubHex},
		{"S", "530000000f6b657973746f726520676f6c64656e", "00" + "00000040" + rfcSigHex},
		{"unknown op", "5800000000", "01" + "00000011" + hexOf([]byte("unknown operation"))},
		// A length over the limit is answered from the header alone (no payload follows).
		{"oversize", "5300100001", "01" + "0000000f" + hexOf([]byte("frame too large"))},
		{"oversize max uint32", "53ffffffff", "01" + "0000000f" + hexOf([]byte("frame too large"))},
	} {
		req, _ := hex.DecodeString(c.req)
		reply, _ := rawExchange(t, sock, req)
		if got := hexOf(reply); got != c.want {
			t.Errorf(wireBreak+"\n got  %s\n want %s", c.name, got, c.want)
		}
	}

	// Boundary: a message of exactly MaxPayload bytes is accepted and signed (reply header
	// 00 00000040, signature verifies); that the next byte is refused is the oversize row.
	msg := make([]byte, MaxPayload)
	req := append([]byte{0x53, 0x00, 0x10, 0x00, 0x00}, msg...)
	reply, _ := rawExchange(t, sock, req)
	pub, _ := hex.DecodeString(rfcPubHex)
	if hexOf(reply[:5]) != "0000000040" || !ed25519.Verify(pub, msg, reply[5:]) {
		t.Errorf(wireBreak, "1 MiB sign: reply header "+hexOf(reply[:5]))
	}

	// Error replies on the unknown-op and oversize paths close the connection (doc: "the
	// connection is closed"); P and S replies leave it open for another request.
	_, c := rawExchange(t, sock, []byte{0x58, 0, 0, 0, 0})
	if n, err := c.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Errorf("connection after an unknown op: read %d, %v; want EOF", n, err)
	}
}
