package agent

import (
	"crypto"

	"github.com/netstar-labs/keystore/pkg/keystore"
)

// ResolveSigner returns a signer from an agent socket if agentSock is set, else from
// the ring at ringPath (key id, "" meaning current), calling passphrase only in the
// ring case.
func ResolveSigner(agentSock, ringPath, id string, passphrase func() ([]byte, error)) (crypto.Signer, error) {
	if agentSock != "" {
		return Dial(agentSock)
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
