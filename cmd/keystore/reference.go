package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

// writeReference renders docs/reference.md from the verb table.
func writeReference(w io.Writer) {
	fmt.Fprintln(w, "# Verb reference")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "*Generated from the command table in `cmd/keystore/verbs.go` — do not edit by hand.")
	fmt.Fprintln(w, "Regenerate with `go test ./cmd/keystore -run TestReference -args -update`.*")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "`keystore <verb> [flags]`. There is no passphrase flag; see the user guide for")
	fmt.Fprintln(w, "passphrase sources.")
	for _, v := range verbs {
		fs := flag.NewFlagSet(v.name, flag.ContinueOnError)
		v.setup(fs, &stdio{out: io.Discard, err: io.Discard})
		fmt.Fprintf(w, "\n## `%s`\n\n%s\n", v.name, v.summary)
		var rows []string
		fs.VisitAll(func(f *flag.Flag) {
			def := f.DefValue
			if f.Name == "keystore" {
				def = "$KEYSTORE_FILE, else ~/.config/keystore/default.ks"
			}
			if def == "" || def == "false" {
				def = "—"
			}
			rows = append(rows, fmt.Sprintf("| `-%s` | %s | %s |", f.Name, f.Usage, def))
		})
		if len(rows) > 0 {
			fmt.Fprintln(w, "\n| Flag | Meaning | Default |\n|---|---|---|")
			fmt.Fprintln(w, strings.Join(rows, "\n"))
		}
	}
}
