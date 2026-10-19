//go:build !darwin

package keychain

import (
	"errors"
	"strings"
	"testing"
)

// Off macOS the keychain source degrades with a clear message (docs/design/scope.md). A stub
// that returned nil,nil would hand callers an empty passphrase, so both calls are pinned.
func TestUnsupportedOffDarwin(t *testing.T) {
	b, err := Get("svc")
	if !errors.Is(err, ErrUnsupported) || b != nil {
		t.Errorf("Get = %q, %v, want nil, ErrUnsupported", b, err)
	}
	if err := Set("svc"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Set = %v, want ErrUnsupported", err)
	}
	if !strings.Contains(ErrUnsupported.Error(), "macOS-only") {
		t.Errorf("message does not say why: %v", ErrUnsupported)
	}
}
