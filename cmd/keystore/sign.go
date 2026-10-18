package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/netstar-labs/keystore/internal/passphrase"
	"github.com/netstar-labs/keystore/pkg/agent"
	"github.com/netstar-labs/keystore/pkg/keystore"
)

// maxMessage is the largest message sign and verify accept: the agent's frame limit,
// applied to both paths so a script behaves the same with or without an agent. Sign a
// digest manifest (e.g. sha256sum output) for anything larger.
const maxMessage = agent.MaxPayload

var errBadSig = errors.New("keystore: signature does not verify")

func setupSign(fs *flag.FlagSet, s *stdio) func() error {
	ring, pf, id := ringFlag(fs), passfileFlag(fs), idFlag(fs, false)
	sock := fs.String("agent", "", "sign through the agent at this socket instead of unlocking the ring")
	in := fs.String("in", "-", "message file; - for stdin")
	out := fs.String("o", "", "write the signature to this new file; default stdout")
	raw := fs.Bool("raw", false, "write the 64 raw signature bytes instead of base64")
	force := fs.Bool("force", false, "replace an existing -o file")
	return func() error {
		if *sock != "" && *id != "" {
			return usageError("-id selects a ring key; the agent serves one key (drop -id or -agent)")
		}
		msg, err := readMessage(s, *in)
		if err != nil {
			return err
		}
		signer, err := agent.ResolveSigner(*sock, *ring, *id, func() ([]byte, error) { return passphrase.Unlock(*pf) })
		if err != nil {
			return err
		}
		sig, err := signer.Sign(nil, msg, crypto.Hash(0))
		if priv, ok := signer.(ed25519.PrivateKey); ok {
			clear(priv)
		}
		if err != nil {
			return err
		}
		b := sig
		if !*raw {
			b = []byte(base64.StdEncoding.EncodeToString(sig) + "\n")
		}
		if *out == "" {
			_, err = s.out.Write(b)
			return err
		}
		if err := writeFile(*out, b, 0o644, *force); err != nil {
			return err
		}
		fmt.Fprintf(s.err, "wrote %s\n", *out)
		return nil
	}
}

func setupVerify(fs *flag.FlagSet, s *stdio) func() error {
	pubFile := fs.String("pub", "", "public key, SPKI PEM (required)")
	sigFile := fs.String("sig", "", "signature file, base64 or 64 raw bytes (required)")
	in := fs.String("in", "-", "message file; - for stdin")
	return func() error {
		if err := need("pub", *pubFile); err != nil {
			return err
		}
		if err := need("sig", *sigFile); err != nil {
			return err
		}
		pemB, err := os.ReadFile(*pubFile)
		if err != nil {
			return err
		}
		pub, err := keystore.ParsePublicKeyPEM(pemB)
		if err != nil {
			return err
		}
		sig, err := readSignature(*sigFile)
		if err != nil {
			return err
		}
		msg, err := readMessage(s, *in)
		if err != nil {
			return err
		}
		if !ed25519.Verify(pub, msg, sig) {
			return errBadSig
		}
		fmt.Fprintf(s.err, "verified: %s\n", keystore.Fingerprint(pub))
		return nil
	}
}

func readMessage(s *stdio, in string) ([]byte, error) {
	var r io.Reader = s.in
	if in != "-" {
		f, err := os.Open(in)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, maxMessage+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxMessage {
		return nil, fmt.Errorf("keystore: message larger than %d bytes; sign a digest manifest instead (e.g. sha256sum FILE > FILE.sha256)", maxMessage)
	}
	return b, nil
}

func readSignature(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) == ed25519.SignatureSize {
		return b, nil
	}
	sig, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(b)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("keystore: signature file is neither base64 nor 64 raw bytes of Ed25519 signature")
	}
	return sig, nil
}
