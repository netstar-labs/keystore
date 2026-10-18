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
