package agent

import (
	"crypto"

	"github.com/netstar-labs/keystore/pkg/keystore"
)

// ResolveSigner returns a signer from an agent socket if agentSock is set, else from
// the ring at ringPath (key id, "" meaning current), calling passphrase only in the
// ring case. On any error the returned Signer is nil.
func ResolveSigner(agentSock, ringPath, id string, passphrase func() ([]byte, error)) (crypto.Signer, error) {
	if agentSock != "" {
		c, err := Dial(agentSock)
		if err != nil {
			return nil, err // not c: a nil *Client in a non-nil interface
		}
		return c, nil
	}
	k, err := keystore.Open(ringPath)
	if err != nil {
		return nil, err
	}
	pw, err := passphrase()
	if err != nil {
		return nil, err
	}
	defer clear(pw)
	return k.Signer(id, pw)
}
