package keychain

import (
	"errors"
	"slices"
	"testing"
)

func TestArgsNeverCarryTheSecret(t *testing.T) {
	set := setArgs("svc")
	if set[len(set)-1] != "-w" {
		t.Fatalf("set args must end with a bare -w so security prompts: %v", set)
	}
	if !slices.Contains(set, "-U") || !slices.Contains(set, Account) {
		t.Fatalf("set args: %v", set)
	}
	if g := getArgs("svc"); g[0] != "find-generic-password" || g[len(g)-1] != "-w" {
		t.Fatalf("get args: %v", g)
	}
}

func TestServiceNamesCannotBeOptions(t *testing.T) {
	for _, s := range []string{"", "-w", "--help", "a b", "x;y"} {
		if _, err := Get(s); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%q) reached security: %v", s, err)
		}
		if err := Set(s); err == nil {
			t.Errorf("Set(%q) accepted", s)
		}
	}
}

// Read-only: looks up a service that does not exist; never writes the keychain.
func TestGetMissing(t *testing.T) {
	if _, err := Get("keystore-test-no-such-service-6e1f"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(missing) = %v, want ErrNotFound", err)
	}
}

// The exact argv and program path handed to security(1). TestArgsNeverCarryTheSecret
// checks the shape (bare trailing -w, -U present); this pins every element and its
// order, because security reads positions and flags: a reordered or renamed flag makes it
// look up (or overwrite) a different keychain item, and a passphrase that does not match
// the stored one then fails as "wrong passphrase", not as a keychain error. Items stored
// by older builds are found only under this service/account pair.
func TestKeychainArgvGolden(t *testing.T) {
	if security != "/usr/bin/security" {
		t.Errorf("security path = %q", security)
	}
	if got, want := getArgs("svc"), []string{"find-generic-password", "-s", "svc", "-a", "keystore", "-w"}; !slices.Equal(got, want) {
		t.Errorf("KEYCHAIN ARGV CHANGED (get): %q, want %q. Existing keychain items are located by these arguments; do not re-record.", got, want)
	}
	if got, want := setArgs("svc"), []string{"add-generic-password", "-s", "svc", "-a", "keystore", "-U", "-w"}; !slices.Equal(got, want) {
		t.Errorf("KEYCHAIN ARGV CHANGED (set): %q, want %q. Existing keychain items are located by these arguments; do not re-record.", got, want)
	}
}
