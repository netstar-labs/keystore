//go:build !linux && !darwin

package peercred

func peerUID(int) (int, error) { return -1, ErrUnsupported }
