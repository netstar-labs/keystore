// Command signed-requests shows service-to-service request signing: service A signs each
// HTTP request through a keystore agent; service B verifies it with nothing but A's
// public key, and rejects tampering, the wrong key, replays and stale timestamps.
//
//	go run ./examples/signed-requests -sock AGENT.sock -pub prod.pub
//
// Both services run in this one process for the demo; in production they are separate
// programs, and only Sign and Verifier are needed.
package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/netstar-labs/keystore/pkg/agent"
	"github.com/netstar-labs/keystore/pkg/keystore"
)

// Scheme is the domain-separation tag: a signature made for this protocol cannot be
// replayed as a signature over any other protocol's bytes, even with the same key.
const Scheme = "keystore-example-request/v1"

// Header names carried on every signed request.
const (
	HdrTimestamp = "X-Sig-Timestamp"
	HdrNonce     = "X-Sig-Nonce"
	HdrSignature = "X-Sig-Signature"
)

// canonical is exactly what gets signed: the scheme, method, path and query, timestamp,
// nonce, and SHA-256 of the body, one per line.
func canonical(method, uri string, ts int64, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return fmt.Appendf(nil, "%s\n%s\n%s\n%d\n%s\n%s", Scheme, method, uri, ts, nonce, hex.EncodeToString(sum[:]))
}

// Sign adds the signature headers to req. body must be the exact bytes sent.
func Sign(req *http.Request, body []byte, s crypto.Signer, now time.Time) error {
	nb := make([]byte, 16)
	if _, err := io.ReadFull(randReader, nb); err != nil {
		return err
	}
	nonce := hex.EncodeToString(nb)
	ts := now.Unix()
	sig, err := s.Sign(nil, canonical(req.Method, req.URL.RequestURI(), ts, nonce, body), crypto.Hash(0))
	if err != nil {
		return err
	}
	req.Header.Set(HdrTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(HdrNonce, nonce)
	req.Header.Set(HdrSignature, base64.StdEncoding.EncodeToString(sig))
	return nil
}

// Verifier is service B's middleware. It needs only the signer's public key.
type Verifier struct {
	Pub     ed25519.PublicKey
	Skew    time.Duration // accepted clock difference, both directions
	MaxBody int64
	Now     func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time // nonce → expiry
}

// Wrap verifies each request before passing it to next; failures get 401.
func (v *Verifier) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, v.MaxBody+1))
		if err != nil || int64(len(body)) > v.MaxBody {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		if err := v.check(r, body); err != nil {
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

func (v *Verifier) check(r *http.Request, body []byte) error {
	ts, err := strconv.ParseInt(r.Header.Get(HdrTimestamp), 10, 64)
	if err != nil {
		return errors.New("missing timestamp")
	}
	nonce := r.Header.Get(HdrNonce)
	if len(nonce) != 32 {
		return errors.New("missing nonce")
	}
	sig, err := base64.StdEncoding.DecodeString(r.Header.Get(HdrSignature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("missing signature")
	}
	now := v.Now()
	if d := now.Sub(time.Unix(ts, 0)); d > v.Skew || d < -v.Skew {
		return errors.New("timestamp outside the accepted window")
	}
	if !ed25519.Verify(v.Pub, canonical(r.Method, r.URL.RequestURI(), ts, nonce, body), sig) {
		return errors.New("bad signature")
	}
	// Only a verified request may consume a nonce, so forgeries cannot fill the cache.
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen == nil {
		v.seen = map[string]time.Time{}
	}
	for n, exp := range v.seen {
		if now.After(exp) {
			delete(v.seen, n)
		}
	}
	if _, dup := v.seen[nonce]; dup {
		return errors.New("replayed request")
	}
	v.seen[nonce] = now.Add(2 * v.Skew)
	return nil
}

func main() {
	sock := flag.String("sock", "", "agent socket (service A's signer)")
	pubFile := flag.String("pub", "", "service A's public key PEM (what service B pins)")
	flag.Parse()
	if *sock == "" || *pubFile == "" {
		fmt.Fprintln(os.Stderr, "usage: signed-requests -sock AGENT.sock -pub prod.pub")
		os.Exit(2)
	}
	if err := demo(*sock, *pubFile, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

// demo runs service B and drives service A's requests against it, checking each outcome.
func demo(sock, pubFile string, out io.Writer) error {
	pemB, err := os.ReadFile(pubFile)
	if err != nil {
		return err
	}
	pub, err := keystore.ParsePublicKeyPEM(pemB)
	if err != nil {
		return err
	}
	signer, err := agent.Dial(sock) // service A: no key, no passphrase — just the socket
	if err != nil {
		return fmt.Errorf("service A cannot reach its signer: %w", err)
	}
	v := &Verifier{Pub: pub, Skew: 30 * time.Second, MaxBody: 1 << 20, Now: time.Now}
	b := httptest.NewServer(v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "accepted")
	})))
	defer b.Close()

	_, stranger, _ := ed25519.GenerateKey(nil)
	body := []byte(`{"order":42}`)
	type tc struct {
		name   string
		signer crypto.Signer
		at     time.Time
		mutate func(*http.Request)
		reuse  bool
		want   int
	}
	var last *http.Request
	cases := []tc{
		{name: "signed request", signer: signer, at: time.Now(), want: 200},
		{name: "replay of that request", reuse: true, want: 401},
		{name: "body changed after signing", signer: signer, at: time.Now(),
			mutate: func(r *http.Request) { r.Body = io.NopCloser(bytes.NewReader([]byte(`{"order":43}`))) }, want: 401},
		{name: "path changed after signing", signer: signer, at: time.Now(),
			mutate: func(r *http.Request) { r.URL.Path = "/refunds" }, want: 401},
		{name: "signed by a different key", signer: stranger, at: time.Now(), want: 401},
		{name: "timestamp 10 minutes old", signer: signer, at: time.Now().Add(-10 * time.Minute), want: 401},
		{name: "unsigned request", want: 401},
	}
	for _, c := range cases {
		var req *http.Request
		if c.reuse {
			req = last.Clone(last.Context())
			req.Body = io.NopCloser(bytes.NewReader(body))
		} else {
			req, _ = http.NewRequest("POST", b.URL+"/orders", bytes.NewReader(body))
			if c.signer != nil {
				if err := Sign(req, body, c.signer, c.at); err != nil {
					return fmt.Errorf("%s: sign: %w", c.name, err)
				}
			}
			if c.mutate != nil {
				c.mutate(req)
			}
			last = req
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("%s: %w", c.name, err)
		}
		msg, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != c.want {
			return fmt.Errorf("%s: got %d (%s), want %d", c.name, resp.StatusCode, bytes.TrimSpace(msg), c.want)
		}
		fmt.Fprintf(out, "ok: %-28s → %d %s\n", c.name, resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}
