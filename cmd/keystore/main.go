// Command keystore manages an encrypted keyring of Ed25519 signing keys.
//
//	keystore <verb> [flags]
//
// Run `keystore help` for the verbs, or see docs/reference.md.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/netstar-labs/keystore/internal/term"
)

// Set by the build: -ldflags "-X main.version=… -X main.build=…".
var version, build = "dev", "none"

type usageError string

func (e usageError) Error() string { return string(e) }

func main() {
	err := run(os.Args[1:], &stdio{in: os.Stdin, out: os.Stdout, err: os.Stderr, inFile: os.Stdin, outFile: os.Stdout})
	os.Exit(report(os.Stderr, err))
}

// Exit statuses. A signature that does not verify has its own code so automation can tell
// "this is bad" from "could not check" (a missing file, an unreadable key).
const (
	exitFailure      = 1
	exitUsage        = 2
	exitBadSignature = 3
)

// report prints err to w and returns the process exit status: 0 for success and help,
// exitUsage for a usage error, exitBadSignature for a signature that does not verify,
// exitFailure for anything else. Messages are cleaned: they can echo input the
// operator's script took from elsewhere.
func report(w io.Writer, err error) int {
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case isUsage(err):
		fmt.Fprintln(w, "keystore:", term.Clean(err.Error()))
		return exitUsage
	case errors.Is(err, errBadSig):
		fmt.Fprintln(w, oneLine(err))
		return exitBadSignature
	default:
		fmt.Fprintln(w, oneLine(err))
		return exitFailure
	}
}

func run(args []string, s *stdio) error {
	if len(args) == 0 {
		usage(s.err)
		return usageError("no verb given")
	}
	name, rest := args[0], args[1:]
	switch name {
	case "help", "-h", "-help", "--help":
		usage(s.out)
		return nil
	case "version", "-version", "--version":
		fmt.Fprintf(s.out, "keystore %s (%s)\n", version, build)
		return nil
	}
	for _, v := range verbs {
		if v.name != name {
			continue
		}
		fs := flag.NewFlagSet("keystore "+v.name, flag.ContinueOnError)
		// The flag package prints its error, an unknown flag name echoed verbatim (newlines
		// included), straight to its output; keep that off the terminal and let report print
		// the returned error cleaned. Usage text is ours: it goes to stderr.
		fs.SetOutput(io.Discard)
		runVerb := v.setup(fs, s)
		fs.Usage = func() {
			fs.SetOutput(s.err)
			fmt.Fprintf(s.err, "keystore %s — %s\n\n", v.name, v.summary)
			fs.PrintDefaults()
		}
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return err
			}
			return usageError(err.Error())
		}
		// sign -agent never reads the ring, so it needs no ring path.
		if f, a := fs.Lookup("keystore"), fs.Lookup("agent"); f != nil && f.Value.String() == "" && (a == nil || a.Value.String() == "") {
			return usageError("no ring path: pass -keystore FILE or set KEYSTORE_FILE (no home directory to default to)")
		}
		if fs.NArg() != 0 {
			return usageError(fmt.Sprintf("%s: unexpected argument %q", v.name, fs.Arg(0)))
		}
		return runVerb()
	}
	usage(s.err)
	return usageError(fmt.Sprintf("unknown verb %q", name))
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: keystore <verb> [flags]   (keystore <verb> -h for flags)")
	fmt.Fprintln(w)
	for _, v := range verbs {
		fmt.Fprintf(w, "  %-12s %s\n", v.name, v.summary)
	}
}

func isUsage(err error) bool {
	var u usageError
	return errors.As(err, &u)
}

// oneLine keeps failure output to a single line, free of terminal-active characters.
func oneLine(err error) string {
	msg := term.Clean(err.Error())
	if !strings.HasPrefix(msg, "keystore") {
		msg = "keystore: " + msg
	}
	return msg
}
