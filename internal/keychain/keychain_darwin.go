package keychain

import (
	"bytes"
	"os"
	"os/exec"
)

// security is a variable only so tests can point it at a shim; nothing else assigns it.
var security = "/usr/bin/security"

// Get returns the passphrase stored for service.
func Get(service string) ([]byte, error) {
	if err := checkService(service); err != nil {
		return nil, err
	}
	out, err := exec.Command(security, getArgs(service)...).Output()
	if err != nil {
		return nil, ErrNotFound
	}
	out = bytes.TrimSuffix(out, []byte("\n"))
	return out, nil
}

// Set stores a passphrase for service, replacing any existing one. security prompts on
// the terminal for the value.
func Set(service string) error {
	if err := checkService(service); err != nil {
		return err
	}
	cmd := exec.Command(security, setArgs(service)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func getArgs(service string) []string {
	return []string{"find-generic-password", "-s", service, "-a", Account, "-w"}
}

// setArgs ends with a bare -w, which makes security prompt for the password rather
// than take it as an argument.
func setArgs(service string) []string {
	return []string{"add-generic-password", "-s", service, "-a", Account, "-U", "-w"}
}
