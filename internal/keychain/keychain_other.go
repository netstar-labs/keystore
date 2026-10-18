//go:build !darwin

package keychain

// Get is unsupported off macOS.
func Get(service string) ([]byte, error) { return nil, ErrUnsupported }

// Set is unsupported off macOS.
func Set(service string) error { return ErrUnsupported }
