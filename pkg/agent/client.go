package agent

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/netstar-labs/keystore/internal/peercred"
)

// DefaultTimeout is the deadline given to each dial and, separately, to the exchange that
// follows it (one deadline over the request write and reply read); a call can therefore
// take up to twice this long.
const DefaultTimeout = 5 * time.Second

// Client is a crypto.Signer backed by an agent socket. It holds no private key.
type Client struct {
	path    string
	pub     ed25519.PublicKey
	Timeout time.Duration
}

// Dial connects to the agent at path, checks that it runs as the current user, and
// fetches its public key.
func Dial(path string) (*Client, error) {
	c := &Client{path: path, Timeout: DefaultTimeout}
	p, err := c.roundTrip(OpPublic, nil)
	if err != nil {
		return nil, err
	}
	if len(p) != ed25519.PublicKeySize {
		return nil, errors.New("keystore agent: bad public key from agent")
	}
	c.pub = ed25519.PublicKey(p)
	return c, nil
}

// Public returns the agent key's ed25519.PublicKey.
func (c *Client) Public() crypto.PublicKey { return c.pub }

// Sign asks the agent to sign message. Only pure Ed25519 is supported: opts must be
// crypto.Hash(0) or an *ed25519.Options with no hash and no context. The returned
// signature is verified against the agent's public key before it is returned.
func (c *Client) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != 0 {
		return nil, errors.New("keystore agent: only pure Ed25519 is supported")
	}
	if o, ok := opts.(*ed25519.Options); ok && o.Context != "" {
		return nil, errors.New("keystore agent: Ed25519 contexts are not supported")
	}
	sig, err := c.roundTrip(OpSign, message)
	if err != nil {
		return nil, err
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(c.pub, message, sig) {
		return nil, errors.New("keystore agent: agent returned an invalid signature")
	}
	return sig, nil
}

// maxStatusText bounds how much of an error reply the client shows; the agent's own
// messages are far shorter.
const maxStatusText = 256

func (c *Client) roundTrip(op byte, payload []byte) ([]byte, error) {
	if len(payload) > MaxPayload {
		return nil, ErrTooLarge
	}
	conn, err := net.DialTimeout("unix", c.path, c.Timeout)
	if err != nil {
		return nil, fmt.Errorf("keystore agent: %w", err)
	}
	defer conn.Close()
	uc := conn.(*net.UnixConn)
	if uid, err := peercred.UID(uc); err != nil || uid != os.Getuid() {
		return nil, fmt.Errorf("keystore agent: socket %s is served by uid %d, not the current user", c.path, uid)
	}
	conn.SetDeadline(time.Now().Add(c.Timeout))
	if err := writeFrame(conn, op, payload); err != nil {
		return nil, err
	}
	status, p, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("keystore agent: %w", err)
	}
	if status != StatusOK {
		// Bytes from the other end of the socket: quoted, and cut short so a hostile peer
		// cannot flood the terminal with a megabyte of status text.
		more := ""
		if len(p) > maxStatusText {
			p, more = p[:maxStatusText], "..."
		}
		return nil, fmt.Errorf("keystore agent: %q%s", p, more)
	}
	return p, nil
}
