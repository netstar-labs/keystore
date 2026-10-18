package keychain

import (
	"errors"
	"testing"

	"github.com/netstar-labs/keystore/internal/ids"
)

// The service-name rule is the entry-id rule; the refusal must come from one place so the
// alphabet in its message cannot drift from the one ids enforces.
func TestCheckServiceUsesTheEntryIDRule(t *testing.T) {
	for _, ok := range []string{"keystore", "a", "my-service.1_x"} {
		if err := checkService(ok); err != nil {
			t.Errorf("checkService(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-flag", "a b", "a;b", "a/b", "x\x1b[31m"} {
		if err := checkService(bad); !errors.Is(err, ids.ErrBadID) {
			t.Errorf("checkService(%q) = %v, want it to wrap ids.ErrBadID", bad, err)
		}
	}
}
