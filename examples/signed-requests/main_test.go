package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netstar-labs/keystore/pkg/agent"
	"github.com/netstar-labs/keystore/pkg/keystore"
)

// startAgent runs an in-process agent for a fresh key and writes its public key PEM.
func startAgent(t *testing.T) (sock, pubFile string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv, err := agent.NewServer(priv)
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := os.MkdirTemp("/tmp", "ksr")
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock = filepath.Join(dir, "a.sock")
	ln, err := agent.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	pemB, _ := keystore.MarshalPublicKeyPEM(pub)
	pubFile = filepath.Join(t.TempDir(), "a.pub")
	os.WriteFile(pubFile, pemB, 0o644)
	return sock, pubFile
}

// The demo itself asserts every case: happy path, replay, tampered body and path,
// wrong key, stale timestamp, unsigned.
func TestDemoCases(t *testing.T) {
	sock, pub := startAgent(t)
	var out bytes.Buffer
	if err := demo(sock, pub, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if n := strings.Count(out.String(), "ok: "); n != 7 {
		t.Fatalf("%d cases reported, want 7:\n%s", n, out.String())
	}
}

func TestAbsentAgent(t *testing.T) {
	_, pub := startAgent(t)
	if err := demo(filepath.Join(t.TempDir(), "none.sock"), pub, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "cannot reach its signer") {
		t.Fatalf("absent agent: %v", err)
	}
}

// A verifier pinned to a different key accepts nothing from this agent.
func TestPinnedToOtherKey(t *testing.T) {
	sock, _ := startAgent(t)
	_, otherPub := startAgent(t)
	if err := demo(sock, otherPub, &bytes.Buffer{}); err == nil {
		t.Fatal("verifier pinned to another key accepted the signed request")
	}
}

func TestCanonicalIsUnambiguous(t *testing.T) {
	a := canonical("POST", "/a", 1, "n", []byte("x"))
	b := canonical("POST", "/a\n1", 1, "n", []byte("x"))
	if bytes.Equal(a, b) {
		t.Fatal("canonical form collides")
	}
	if !bytes.HasPrefix(a, []byte(Scheme+"\n")) {
		t.Fatal("canonical form lacks the domain-separation tag")
	}
}
