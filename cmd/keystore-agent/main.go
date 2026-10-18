// Command keystore-agent unlocks one signing key from a ring, holds it only in memory,
// and signs on request over an owner-only unix socket.
//
//	keystore-agent -keystore K [-id ID] -sock PATH [-passfile P] [-ttl 8h] [-idle 30m]
//
// The passphrase comes from KEYSTORE_PASSPHRASE or -passfile; a daemon never prompts
// and never reads the keychain. The environment variable is cleared from the agent's own
// environment once read (children and os.Environ no longer see it), but the block the
// process started with stays readable by the same user (ps eww, /proc/PID/environ), so
// prefer -passfile. There is no default ring: -keystore (or $KEYSTORE_FILE) and -sock are
// required. The socket is removed on SIGINT, SIGTERM, or when -ttl or
// -idle expires; the process then exits 0.
package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/netstar-labs/keystore/internal/passphrase"
	"github.com/netstar-labs/keystore/pkg/agent"
	"github.com/netstar-labs/keystore/pkg/keystore"
)

// Set by the build: -ldflags "-X main.version=… -X main.build=…".
var version, build = "dev", "none"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "keystore-agent:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("keystore-agent", flag.ContinueOnError)
	ring := fs.String("keystore", os.Getenv("KEYSTORE_FILE"), "ring file (env KEYSTORE_FILE)")
	id := fs.String("id", "", "signing key id (default: the ring's current key)")
	sock := fs.String("sock", "", "unix socket path; its directory must be 0700 and yours (required)")
	pf := fs.String("passfile", "", "read the passphrase from this file (0600, owned by you)")
	ttl := fs.Duration("ttl", 8*time.Hour, "stop after this long; 0 = no limit")
	idle := fs.Duration("idle", 30*time.Minute, "stop after this long without a request; 0 = no limit")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Printf("keystore-agent %s (%s)\n", version, build)
		return nil
	}
	if *ring == "" || *sock == "" || fs.NArg() != 0 {
		fs.Usage()
		return errors.New("-keystore and -sock are required")
	}
	if *ttl < 0 || *idle < 0 {
		return agent.ErrNegativeLifetime // before the passphrase is read
	}
	sockPath, err := filepath.Abs(*sock)
	if err != nil {
		return err
	}

	// A daemon has no terminal and must not block on one, nor pop keychain dialogs.
	passphrase.Prompt = func(string) ([]byte, error) {
		return nil, errors.New("no passphrase: set KEYSTORE_PASSPHRASE or use -passfile (the agent never prompts)")
	}
	if os.Getenv(passphrase.KeychainVar) != "" {
		return errors.New(passphrase.KeychainVar + " is set; the agent reads the passphrase only from KEYSTORE_PASSPHRASE or -passfile")
	}

	k, err := keystore.Open(*ring)
	if err != nil {
		return err
	}
	pw, err := passphrase.Unlock(*pf)
	os.Unsetenv(passphrase.EnvVar)
	if err != nil {
		return err
	}
	signer, err := k.Signer(*id, pw)
	clear(pw)
	if err != nil {
		return err
	}
	priv := signer.(ed25519.PrivateKey)
	defer clear(priv) // drop the key on every exit path

	srv, err := agent.NewServer(priv)
	if err != nil {
		return err
	}
	srv.TTL, srv.Idle = *ttl, *idle
	srv.Log = log.Printf
	ln, err := agent.Listen(sockPath)
	if err != nil {
		return err
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sig
		log.Printf("keystore-agent: %v; stopping", s)
		srv.Close()
	}()

	kid := *id
	if kid == "" {
		kid = k.CurrentID()
	}
	log.Printf("keystore-agent: serving %s (%s) on %s; ttl %v, idle %v; key in memory only",
		kid, keystore.Fingerprint(priv.Public().(ed25519.PublicKey)), sockPath, *ttl, *idle)
	err = srv.Serve(ln)
	if errors.Is(err, agent.ErrExpired) {
		log.Printf("keystore-agent: ttl or idle limit reached; stopping")
		return nil
	}
	return err
}
