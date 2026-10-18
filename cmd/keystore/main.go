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

// report prints err to w and returns the process exit status: 0 for success and help, 2
// for a usage error, 1 for anything else. Messages are cleaned: they can echo input the
// operator's script took from elsewhere.
func report(w io.Writer, err error) int {
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case isUsage(err):
		fmt.Fprintln(w, "keystore:", term.Clean(err.Error()))
		return 2
	default:
		fmt.Fprintln(w, oneLine(err))
		return 1
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
		fs.SetOutput(term.Writer(s.err)) // the flag package echoes an unknown flag name verbatim
		runVerb := v.setup(fs, s)
		fs.Usage = func() {
			fmt.Fprintf(s.err, "keystore %s — %s\n\n", v.name, v.summary)
			fs.PrintDefaults()
		}
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return err
			}
			return usageError(err.Error())
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
