// Package agent holds one Ed25519 key in memory and signs with it on request over an
// owner-only unix socket, so the processes that need signatures never hold the key or
// its passphrase. The client side is a crypto.Signer.
//
// The agent checks who is asking — the peer's uid, as recorded by the kernel, must equal
// its own — but not what is being signed. Use a dedicated key per purpose and
// domain-separate the messages your protocol signs.
package agent

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/netstar-labs/keystore/internal/peercred"
)

var (
	// ErrInUse reports that a live agent already answers on the socket path.
	ErrInUse = errors.New("keystore agent: another agent is already listening on that socket")
	// ErrExpired is returned by Serve when the agent stopped because its TTL or idle
	// limit was reached.
	ErrExpired = errors.New("keystore agent: lifetime or idle limit reached")
)

// Server serves one signing key.
type Server struct {
	signer crypto.Signer
	pub    ed25519.PublicKey

	// TTL stops the agent this long after Serve starts; 0 means no limit.
	TTL time.Duration
	// Idle stops the agent after this long with no successful request; 0 means no limit.
	Idle time.Duration
	// IOTimeout bounds each request's read and reply write. Default 5 s.
	IOTimeout time.Duration
	// Log, if set, receives one line per rejected connection or error. Never secrets.
	Log func(format string, args ...any)

	uidOf func(*net.UnixConn) (int, error) // peer uid lookup; tests replace it

	mu      sync.Mutex
	ln      *net.UnixListener
	closed  bool // Close was called, possibly before Serve
	expired bool
	touch   chan struct{}
}

// NewServer returns a server for an Ed25519 signer.
func NewServer(signer crypto.Signer) (*Server, error) {
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("keystore agent: signer is not ed25519")
	}
	return &Server{signer: signer, pub: pub, IOTimeout: 5 * time.Second, uidOf: peercred.UID}, nil
}

// Listen creates the agent socket at path. The parent directory must be owned by the
// caller and closed to group and others. An existing socket that a live agent answers
// on is ErrInUse; a stale one is removed; anything else at path is refused.
func Listen(path string) (*net.UnixListener, error) {
	if err := checkDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("keystore agent: %s exists and is not a socket", path)
		}
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, ErrInUse
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	old := syscall.Umask(0o177) // no window in which the socket is reachable by others
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func checkDir(dir string) error {
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(sys.Uid) != os.Getuid() {
		return fmt.Errorf("keystore agent: socket directory %s is not owned by the current user", dir)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("keystore agent: socket directory %s is mode %v; it must be 0700", dir, st.Mode().Perm())
	}
	return nil
}

// Serve answers requests on ln until Close, or until TTL or Idle expires (then it
// returns ErrExpired). The socket is removed when the listener closes.
func (s *Server) Serve(ln *net.UnixListener) error {
	s.mu.Lock()
	if s.closed { // Close won the race with Serve
		s.mu.Unlock()
		return ln.Close()
	}
	s.ln = ln
	s.touch = make(chan struct{}, 1)
	s.mu.Unlock()

	stop := make(chan struct{})
	defer close(stop)
	go s.watch(stop)

	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			s.mu.Lock()
			expired := s.expired
			s.mu.Unlock()
			if expired {
				return ErrExpired
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(c)
		}()
	}
}

// watch enforces TTL and Idle by closing the listener.
func (s *Server) watch(stop <-chan struct{}) {
	var ttl, idle <-chan time.Time
	if s.TTL > 0 {
		t := time.NewTimer(s.TTL)
		defer t.Stop()
		ttl = t.C
	}
	var idleT *time.Timer
	if s.Idle > 0 {
		idleT = time.NewTimer(s.Idle)
		defer idleT.Stop()
		idle = idleT.C
	}
	for {
		select {
		case <-stop:
			return
		case <-s.touch:
			if idleT != nil {
				idleT.Reset(s.Idle)
			}
		case <-ttl:
			s.expire()
			return
		case <-idle:
			s.expire()
			return
		}
	}
}

func (s *Server) expire() {
	s.mu.Lock()
	s.expired = true
	ln := s.ln
	s.mu.Unlock()
	ln.Close()
}

// Close stops the server and removes the socket. It is safe to call before, during or
// after Serve, and more than once.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	s.mu.Unlock()
	if ln == nil {
		return nil
	}
	if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func (s *Server) logf(format string, args ...any) {
	if s.Log != nil {
		s.Log(format, args...)
	}
}

func (s *Server) handle(c *net.UnixConn) {
	defer c.Close()
	uid, err := s.uidOf(c)
	if err != nil || uid != os.Getuid() {
		s.logf("rejected connection: peer uid %d (want %d) %v", uid, os.Getuid(), err)
		return
	}
	for {
		c.SetDeadline(time.Now().Add(s.IOTimeout))
		op, p, err := readFrame(c)
		if err != nil {
			if errors.Is(err, ErrTooLarge) {
				writeFrame(c, StatusErr, []byte("frame too large"))
				s.logf("rejected oversize frame")
			}
			return
		}
		var reply []byte
		switch op {
		case OpPublic:
			reply = s.pub
		case OpSign:
			sig, err := s.signer.Sign(nil, p, crypto.Hash(0))
			if err != nil {
				writeFrame(c, StatusErr, []byte("sign failed"))
				s.logf("sign: %v", err)
				return
			}
			reply = sig
		default:
			writeFrame(c, StatusErr, []byte("unknown operation"))
			return
		}
		if err := writeFrame(c, StatusOK, reply); err != nil {
			return
		}
		select {
		case s.touch <- struct{}{}:
		default:
		}
	}
}
