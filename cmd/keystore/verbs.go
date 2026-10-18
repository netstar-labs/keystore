package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/netstar-labs/keystore/internal/passphrase"
	"github.com/netstar-labs/keystore/pkg/keystore"
)

// A verb is one subcommand. The table below drives dispatch, help and the generated
// docs/reference.md, so the three cannot drift apart.
type verb struct {
	name    string
	summary string
	// setup registers the verb's flags and returns the function that runs it.
	setup func(fs *flag.FlagSet, io *stdio) func() error
}

type stdio struct {
	in       io.Reader
	out, err io.Writer
	inFile   *os.File // for terminal detection; nil in tests
	outFile  *os.File // for terminal detection; nil in tests
}

var verbs = []verb{
	{"init", "create an empty ring (mode 0600); never overwrites", setupInit},
	{"keygen", "create the ring if missing, then mint a signing key", setupKeygen},
	{"add", "mint another signing key in an existing ring", setupAdd},
	{"import", "encrypt an existing PKCS#8 PEM Ed25519 private key into the ring", setupImport},
	{"list", "list entries: current marker, id, kind, created, fingerprint (no passphrase)", setupList},
	{"use", "make an entry the current signing key", setupUse},
	{"rm", "remove an entry; the last signing key needs -force", setupRm},
	{"export-pub", "write a public key as SPKI PEM (no passphrase)", setupExportPub},
	{"export-priv", "write a private key as PKCS#8 PEM, for backup or migration (guarded)", setupExportPriv},
	{"add-secret", "mint a random 32-byte secret (never printed; use export-secret)", setupAddSecret},
	{"import-secret", "store a base64 secret read from -in FILE or stdin (prompted without echo on a terminal)", setupImportSecret},
	{"export-secret", "write a secret as base64 (guarded)", setupExportSecret},
	{"passwd", "change the ring passphrase and re-encrypt every entry", setupPasswd},
	{"keychain-set", "store the ring passphrase in the macOS login keychain (security prompts for it)", setupKeychainSet},
	{"sign", "sign up to 1 MiB from -in FILE or stdin with a ring key or an agent; prints a base64 signature", setupSign},
	{"verify", "verify a signature over -in FILE or stdin with a public key PEM; no ring needed", setupVerify},
}

// DefaultRing is used when neither -keystore nor KEYSTORE_FILE is given.
func defaultRing() string {
	if v := os.Getenv("KEYSTORE_FILE"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "default.ks"
	}
	return filepath.Join(home, ".config", "keystore", "default.ks")
}

func ringFlag(fs *flag.FlagSet) *string {
	return fs.String("keystore", defaultRing(), "ring file (env KEYSTORE_FILE)")
}

func passfileFlag(fs *flag.FlagSet) *string {
	return fs.String("passfile", "", "read the passphrase from this file (0600, owned by you)")
}

func idFlag(fs *flag.FlagSet, required bool) *string {
	if required {
		return fs.String("id", "", "entry id (required)")
	}
	return fs.String("id", "", "entry id (default: the current signing key)")
}

func need(name, v string) error {
	if v == "" {
		return usageError("-" + name + " is required")
	}
	return nil
}

// ensureDir creates the default ring's directory owner-only. Other paths are the
// caller's responsibility.
func ensureDir(ring string) error {
	if ring != defaultRing() {
		return nil
	}
	return os.MkdirAll(filepath.Dir(ring), 0o700)
}

// ringPassphrase returns a passphrase for adding to k: a new one (confirmed, length-
// checked) if the ring is empty, else the existing one.
func ringPassphrase(k *keystore.Keystore, passfile string) ([]byte, error) {
	if len(k.List()) == 0 {
		return passphrase.New(passfile)
	}
	return passphrase.Unlock(passfile)
}

func setupInit(fs *flag.FlagSet, s *stdio) func() error {
	ring := ringFlag(fs)
	return func() error {
		if err := ensureDir(*ring); err != nil {
			return err
		}
		if _, err := keystore.Create(*ring); err != nil {
			return err
		}
		fmt.Fprintf(s.err, "created %s\n", *ring)
		return nil
	}
}

func setupKeygen(fs *flag.FlagSet, s *stdio) func() error {
	ring, pf, id := ringFlag(fs), passfileFlag(fs), idFlag(fs, true)
	return func() error {
		if err := need("id", *id); err != nil {
			return err
		}
		if err := ensureDir(*ring); err != nil {
			return err
		}
		k, err := keystore.OpenOrCreate(*ring)
		if err != nil {
			return err
		}
		return addKey(k, *id, *pf, s)
	}
}

func setupAdd(fs *flag.FlagSet, s *stdio) func() error {
	ring, pf, id := ringFlag(fs), passfileFlag(fs), idFlag(fs, true)
	return func() error {
		if err := need("id", *id); err != nil {
			return err
		}
		k, err := keystore.Open(*ring)
		if err != nil {
			return err
		}
		return addKey(k, *id, *pf, s)
	}
}

func addKey(k *keystore.Keystore, id, pf string, s *stdio) error {
	pw, err := ringPassphrase(k, pf)
	if err != nil {
		return err
	}
	defer clear(pw)
	pub, err := k.Add(id, pw)
	if err != nil {
		return err
	}
	pemB, err := keystore.MarshalPublicKeyPEM(pub)
	if err != nil {
		return err
	}
	fmt.Fprintf(s.err, "added %s (current: %s) %s\n", id, k.CurrentID(), keystore.Fingerprint(pub))
	_, err = s.out.Write(pemB)
	return err
}

func setupImport(fs *flag.FlagSet, s *stdio) func() error {
	ring, pf, id := ringFlag(fs), passfileFlag(fs), idFlag(fs, true)
	keyFile := fs.String("key", "", "PKCS#8 PEM private key file to import (required)")
	return func() error {
		if err := need("id", *id); err != nil {
			return err
		}
		if err := need("key", *keyFile); err != nil {
			return err
		}
		b, err := readLimited(*keyFile, maxInputFile)
		if err != nil {
			return err
		}
		defer clear(b)
		priv, err := keystore.ParsePrivateKeyPEM(b)
		if err != nil {
			return err
		}
		defer clear(priv)
		k, err := keystore.Open(*ring)
		if err != nil {
			return err
		}
		pw, err := ringPassphrase(k, *pf)
		if err != nil {
			return err
		}
		defer clear(pw)
		if err := k.Import(*id, priv, pw); err != nil {
			return err
		}
		fmt.Fprintf(s.err, "imported %s (current: %s); remove the plaintext file %s\n", *id, k.CurrentID(), *keyFile)
		return nil
	}
}

func setupList(fs *flag.FlagSet, s *stdio) func() error {
	ring := ringFlag(fs)
	return func() error {
		k, err := keystore.Open(*ring)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(s.out, 0, 0, 2, ' ', 0)
		for _, e := range k.List() {
			mark := " "
			if e.Current {
				mark = "*"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", mark, e.ID, e.Kind, e.Created.Format(time.RFC3339), e.Fingerprint)
		}
		return tw.Flush()
	}
}

func setupUse(fs *flag.FlagSet, s *stdio) func() error {
	ring, id := ringFlag(fs), idFlag(fs, true)
	return func() error {
		if err := need("id", *id); err != nil {
			return err
		}
		k, err := keystore.Open(*ring)
		if err != nil {
			return err
		}
		if err := k.Use(*id); err != nil {
			return err
		}
		fmt.Fprintf(s.err, "current: %s\n", *id)
		return nil
	}
}

func setupRm(fs *flag.FlagSet, s *stdio) func() error {
	ring, id := ringFlag(fs), idFlag(fs, true)
	force := fs.Bool("force", false, "allow removing the last signing key")
	return func() error {
		if err := need("id", *id); err != nil {
			return err
		}
		k, err := keystore.Open(*ring)
		if err != nil {
			return err
		}
		if err := k.Remove(*id, *force); err != nil {
			return err
		}
		fmt.Fprintf(s.err, "removed %s (current: %s)\n", *id, k.CurrentID())
		return nil
	}
}

func setupExportPub(fs *flag.FlagSet, s *stdio) func() error {
	ring, id := ringFlag(fs), idFlag(fs, false)
	return func() error {
		k, err := keystore.Open(*ring)
		if err != nil {
			return err
		}
		pub, err := k.Public(*id)
		if err != nil {
			return err
		}
		b, err := keystore.MarshalPublicKeyPEM(pub)
		if err != nil {
			return err
		}
		_, err = s.out.Write(b)
		return err
	}
}

func setupExportPriv(fs *flag.FlagSet, s *stdio) func() error {
	ring, pf, id := ringFlag(fs), passfileFlag(fs), idFlag(fs, false)
	out := fs.String("o", "", "write to this new file (0600); default stdout")
	force := fs.Bool("force", false, "replace an existing -o file, or allow writing to a terminal")
	return func() error {
		k, err := keystore.Open(*ring)
		if err != nil {
			return err
		}
		// Refuse a terminal before asking for the passphrase, not after.
		if err := guardTerminal(s, *out, *force, "a private key"); err != nil {
			return err
		}
		pw, err := passphrase.Unlock(*pf)
		if err != nil {
			return err
		}
		defer clear(pw)
		priv, err := k.ExportPrivate(*id, pw)
		if err != nil {
			return err
		}
		defer clear(priv)
		b, err := keystore.MarshalPrivateKeyPEM(priv)
		if err != nil {
			return err
		}
		defer clear(b)
		return emit(s, *out, *force, b, "PKCS#8")
	}
}
