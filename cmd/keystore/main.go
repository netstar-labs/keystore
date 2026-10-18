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
	"unicode"
)

// Set by the build: -ldflags "-X main.version=… -X main.build=…".
var version, build = "dev", "none"

type usageError string

func (e usageError) Error() string { return string(e) }

func main() {
	err := run(os.Args[1:], &stdio{in: os.Stdin, out: os.Stdout, err: os.Stderr, inFile: os.Stdin, outFile: os.Stdout})
	switch {
	case err == nil:
	case errors.Is(err, flag.ErrHelp):
	case isUsage(err):
		fmt.Fprintln(os.Stderr, "keystore:", err)
		os.Exit(2)
	default:
		fmt.Fprintln(os.Stderr, oneLine(err))
		os.Exit(1)
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
		fs.SetOutput(s.err)
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

// oneLine keeps failure output to a single line, and free of control characters: the
// message can echo a file name or OS error text the operator's script took from elsewhere,
// and an escape sequence or carriage return there must not act on the terminal.
func oneLine(err error) string {
	msg := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, err.Error())
	if !strings.HasPrefix(msg, "keystore") {
		msg = "keystore: " + msg
	}
	return msg
}
