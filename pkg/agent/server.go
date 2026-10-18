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
	// ErrNegativeLifetime is returned by Serve when TTL or Idle is negative; 0 is the
	// spelling for "no limit".
	ErrNegativeLifetime = errors.New("keystore agent: ttl and idle must not be negative (0 means no limit)")
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
	ln      *Listener
	conns   map[*net.UnixConn]struct{} // open connections, closed on stop
	closed  bool                       // stopped by Close (possibly before Serve) or expiry
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

// Listener is an agent socket plus the exclusive lock that owns its path.
type Listener struct {
	*net.UnixListener
	lock *os.File
}

// Close closes the socket (removing it) and then releases the path lock.
func (l *Listener) Close() error {
	err := l.UnixListener.Close()
	l.lock.Close() // closing the descriptor releases the flock
	return err
}

// Listen creates the agent socket at path. The parent directory must be owned by the
// caller and closed to group and others.
//
// Ownership of the path is decided by an exclusive flock on path+".lock", held until the
// listener is closed: a second agent — even one racing this one — gets ErrInUse and never
// touches the socket. An existing socket that something still answers on is also
// ErrInUse; a stale one is removed; anything else at path is refused.
func Listen(path string) (*Listener, error) {
	if err := checkDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrInUse
		}
		return nil, err
	}
	ln, err := listenLocked(path)
	if err != nil {
		lock.Close()
		return nil, err
	}
	return &Listener{UnixListener: ln, lock: lock}, nil
}

func listenLocked(path string) (*net.UnixListener, error) {
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
func (s *Server) Serve(ln *Listener) error {
	if s.TTL < 0 || s.Idle < 0 { // timers arm only for values > 0: a negative one would mean "no limit"
		ln.Close()
		return ErrNegativeLifetime
	}
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
		if !s.track(c) {
			c.Close() // stopping: accept raced with shutdown
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.untrack(c)
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
	s.mu.Unlock()
	s.Close()
}

// Close stops the server: it closes the listener (removing the socket) and every open
// connection, so no request is served after it returns and Serve can exit. It is safe to
// call before, during or after Serve, and more than once.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	conns := s.conns
	s.conns = nil
	s.mu.Unlock()
	for c := range conns {
		c.Close()
	}
	if ln == nil {
		return nil
	}
	if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// track registers an accepted connection; it reports false if the server is stopping.
func (s *Server) track(c *net.UnixConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if s.conns == nil {
		s.conns = map[*net.UnixConn]struct{}{}
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c *net.UnixConn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
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
