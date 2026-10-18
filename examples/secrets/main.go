// Command secrets shows a workload loading an opaque secret from the ring at start-up and
// dropping it as soon as it has derived what it needs — here, an HMAC key that tags
// outbound messages.
//
//	go run ./examples/secrets -keystore prod.ks -id hmac -passfile pass -msg "hello"
//
// The alternative this replaces — the secret in an environment variable — leaves it
// readable for the life of the process (and, on Linux, in /proc/PID/environ to the same
// user), inherited by every child process, and frequently dumped into crash reports and
// debug logs.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/netstar-labs/keystore/pkg/keystore"
)

func main() {
	ring := flag.String("keystore", "", "ring file")
	id := flag.String("id", "", "secret id")
	pf := flag.String("passfile", "", "passphrase file (0600)")
	msg := flag.String("msg", "", "message to tag")
	flag.Parse()
	if err := run(*ring, *id, *pf, *msg, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "secrets:", err)
		os.Exit(1)
	}
}

func run(ring, id, passfile, msg string, out io.Writer) error {
	pw, err := readPassfile(passfile)
	if err != nil {
		return err
	}
	k, err := keystore.Open(ring)
	if err != nil {
		clear(pw)
		return err
	}
	sec, err := k.Secret(id, pw)
	clear(pw)
	if err != nil {
		return err
	}
	tag := Tag(sec, []byte(msg))
	clear(sec) // best effort: Go cannot promise no other copy exists, but keep none on purpose
	fmt.Fprintf(out, "%s\n", hex.EncodeToString(tag))
	return nil
}

// Tag is HMAC-SHA256(key, msg).
func Tag(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// readPassfile reads a passphrase file, refusing one readable by group or others (the
// keystore CLI applies the same rule).
func readPassfile(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("passfile must be 0600 or stricter")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(bytes.TrimSuffix(b, []byte("\n")), []byte("\r")), nil
}
