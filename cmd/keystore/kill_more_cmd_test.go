package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netstar-labs/keystore/internal/passphrase"
)

// passwd refuses a new passphrase equal to the current one, and accepts one that merely has
// the same length: the comparison is of the values, not their sizes.
func TestPasswdSamePassphraseCheckComparesValues(t *testing.T) {
	r := ring(t) // KEYSTORE_PASSPHRASE = testPass
	if _, _, err := cli(t, "keygen", "-keystore", r, "-id", "a"); err != nil {
		t.Fatal(err)
	}
	sameLen := strings.Repeat("x", len(testPass))
	t.Setenv("KEYSTORE_NEW_PASSPHRASE", sameLen)
	if _, _, err := cli(t, "passwd", "-keystore", r); err != nil {
		t.Fatalf("a different passphrase of the same length was refused: %v", err)
	}
	t.Setenv("KEYSTORE_PASSPHRASE", sameLen) // now current
	if _, _, err := cli(t, "passwd", "-keystore", r); err == nil || !strings.Contains(err.Error(), "same") {
		t.Fatalf("passwd to the identical passphrase: %v, want the same-passphrase refusal", err)
	}
	t.Setenv("KEYSTORE_NEW_PASSPHRASE", sameLen+"y") // longer, different
	if _, _, err := cli(t, "passwd", "-keystore", r); err != nil {
		t.Fatalf("a longer new passphrase was refused: %v", err)
	}
}

// verify covers the whole message: a change anywhere in it, including far past the first
// bytes, is a bad signature.
func TestVerifyCoversTheWholeMessage(t *testing.T) {
	r, pub, _ := signFixture(t)
	dir := t.TempDir()
	msg := bytes.Repeat([]byte("0123456789"), 20) // 200 bytes
	mf := filepath.Join(dir, "msg")
	os.WriteFile(mf, msg, 0o644)
	sigOut, _, err := cli(t, "sign", "-keystore", r, "-in", mf)
	if err != nil {
		t.Fatal(err)
	}
	sf := filepath.Join(dir, "sig")
	os.WriteFile(sf, []byte(sigOut), 0o644)
	if _, _, err := cli(t, "verify", "-pub", pub, "-sig", sf, "-in", mf); err != nil {
		t.Fatalf("verify of the untouched message: %v", err)
	}
	for _, at := range []int{0, 31, 32, 33, 100, 199} {
		bad := append([]byte(nil), msg...)
		bad[at] ^= 1
		bf := filepath.Join(dir, "bad")
		os.WriteFile(bf, bad, 0o644)
		if _, _, err := cli(t, "verify", "-pub", pub, "-sig", sf, "-in", bf); !errors.Is(err, errBadSig) {
			t.Errorf("byte %d flipped: %v, want errBadSig", at, err)
		}
	}
	extra := filepath.Join(dir, "extra")
	os.WriteFile(extra, append(append([]byte(nil), msg...), 'x'), 0o644)
	if _, _, err := cli(t, "verify", "-pub", pub, "-sig", sf, "-in", extra); !errors.Is(err, errBadSig) {
		t.Errorf("appended byte: %v, want errBadSig", err)
	}
}

// export-priv refuses a terminal before it asks for the passphrase: a refusal costs the
// operator nothing, and the passphrase is never typed for an output that will be refused.
func TestExportPrivRefusesTheTerminalBeforePromptingForThePassphrase(t *testing.T) {
	r := ring(t)
	if _, _, err := cli(t, "keygen", "-keystore", r, "-id", "a"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYSTORE_PASSPHRASE", "")
	prompts := 0
	oldP, oldT := passphrase.Prompt, isTerminal
	passphrase.Prompt = func(string) ([]byte, error) { prompts++; return nil, errors.New("test must not prompt") }
	isTerminal = func(*os.File) bool { return true }
	defer func() { passphrase.Prompt, isTerminal = oldP, oldT }()
	fake, _ := os.CreateTemp(t.TempDir(), "tty")
	defer fake.Close()
	var out bytes.Buffer
	for _, verb := range [][]string{{"export-priv", "-keystore", r}, {"export-secret", "-keystore", r, "-id", "a"}} {
		err := run(verb, &stdio{out: &out, err: &out, outFile: fake})
		if err == nil || !strings.Contains(err.Error(), "terminal") {
			t.Errorf("%v: err = %v, want the terminal refusal", verb, err)
		}
	}
	if prompts != 0 {
		t.Errorf("the passphrase was asked for %d times before the terminal refusal", prompts)
	}
}
