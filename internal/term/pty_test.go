package term

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// End-to-end tests of ReadPassword on a real pseudo-terminal. ReadPassword opens
// /dev/tty, which a test process does not have, so each test re-executes this test
// binary (TestPTYChild below) as a session leader whose controlling terminal is the
// slave of a pty the test owns, and plays the user on the master side. The child's
// stdin is a pipe, not the terminal: reading the passphrase from anywhere but /dev/tty
// would hang the test.

const childEnv = "KEYSTORE_PTY_CHILD"

const prompt = "Password: "

// TestPTYChild is the child half. It is a test only so the re-exec'd binary can run it;
// outside a PTY test it skips.
func TestPTYChild(t *testing.T) {
	if os.Getenv(childEnv) == "" {
		t.Skip("helper process for the PTY tests")
	}
	line, err := ReadPassword(prompt)
	fmt.Printf("RESULT %q %v\n", line, err)
	io.Copy(io.Discard, os.Stdin) // hold the process (and so the session) open until the parent says done
}

type ptyChild struct {
	t      *testing.T
	master *os.File
	slave  *os.File // held by the parent too, so the terminal's state outlives the child
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  chan string

	mu  sync.Mutex
	out []byte // everything the terminal has shown the "user"
	// termios of the tty before the child started
	orig *unix.Termios
}

// startChild runs the child with the pty slave as controlling terminal (ctty) or in a
// fresh session with no controlling terminal at all.
func startChild(t *testing.T, ctty bool) *ptyChild {
	t.Helper()
	master, slavePath, err := openPTY()
	if err != nil {
		t.Skipf("cannot build a pty here: %v", err)
	}
	slave, err := os.OpenFile(slavePath, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		t.Skipf("cannot open the pty slave %s: %v", slavePath, err)
	}
	p := &ptyChild{t: t, master: master, slave: slave, lines: make(chan string, 16)}
	t.Cleanup(func() { master.Close(); slave.Close() })
	p.orig, err = unix.IoctlGetTermios(int(master.Fd()), ioctlGetTermios)
	if err != nil {
		t.Skipf("cannot read the pty's termios from its master: %v", err)
	}

	args := []string{"-test.run=^TestPTYChild$"}
	if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+f.Value.String()) // so the child's coverage counts
	}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), childEnv+"=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	p.stdin, err = cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if ctty {
		cmd.ExtraFiles = []*os.File{slave} // fd 3 in the child
		cmd.SysProcAttr.Setctty, cmd.SysProcAttr.Ctty = true, 3
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p.cmd = cmd
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("child stderr:\n%s", stderr.String())
		}
	})
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			p.mu.Lock()
			p.out = append(p.out, buf[:n]...)
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "RESULT ") {
				p.lines <- strings.TrimPrefix(sc.Text(), "RESULT ")
			}
		}
		close(p.lines)
	}()
	return p
}

func (p *ptyChild) shown() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return string(p.out)
}

// waitPrompt blocks until the prompt has reached the terminal: by then ReadPassword has
// already switched echo off and installed its signal handlers.
func (p *ptyChild) waitPrompt() {
	p.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(p.shown(), prompt) {
		if time.Now().After(deadline) {
			p.t.Fatalf("no prompt on the terminal; saw %q", p.shown())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (p *ptyChild) termios() *unix.Termios {
	p.t.Helper()
	tio, err := unix.IoctlGetTermios(int(p.master.Fd()), ioctlGetTermios)
	if err != nil {
		p.t.Fatal(err)
	}
	return tio
}

func (p *ptyChild) type_(s string) {
	p.t.Helper()
	if _, err := p.master.WriteString(s); err != nil {
		p.t.Fatal(err)
	}
}

func (p *ptyChild) result() string {
	p.t.Helper()
	select {
	case l, ok := <-p.lines:
		if !ok {
			p.t.Fatal("child ended without a result")
		}
		return l
	case <-time.After(10 * time.Second):
		p.t.Fatalf("child gave no result; terminal showed %q", p.shown())
		return ""
	}
}

// finish lets the child exit normally and reports its exit code.
func (p *ptyChild) finish() int {
	p.t.Helper()
	p.stdin.Close()
	return p.wait()
}

func (p *ptyChild) wait() int {
	p.t.Helper()
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case err := <-done:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		if err != nil {
			p.t.Fatal(err)
		}
		return 0
	case <-time.After(10 * time.Second):
		p.t.Fatal("child did not exit")
		return -1
	}
}

func echoOn(t *unix.Termios) bool { return t.Lflag&unix.ECHO != 0 }

func TestPTYIsTerminal(t *testing.T) {
	p := startChild(t, true)
	if !IsTerminal(p.slave.Fd()) || !IsTerminal(p.master.Fd()) {
		t.Fatal("a pty end is not reported as a terminal")
	}
	p.stdin.Close()
}

func TestPTYReadPassword(t *testing.T) {
	p := startChild(t, true)
	if !echoOn(p.orig) {
		t.Skip("a fresh pty has echo off here; the test could not tell the prompt turned it off")
	}
	p.waitPrompt()

	during := p.termios()
	if echoOn(during) {
		t.Fatal("echo is ON while the prompt waits")
	}
	if during.Lflag&unix.ICANON == 0 || during.Lflag&unix.ISIG == 0 {
		t.Errorf("prompt mode lost line editing or signals: lflag %#x", during.Lflag)
	}

	p.type_("hunter2\n")
	if got, want := p.result(), `"hunter2" <nil>`; got != want {
		t.Fatalf("ReadPassword returned %s, want %s", got, want)
	}
	if strings.Contains(p.shown(), "hunter2") {
		t.Errorf("the typed passphrase was echoed to the terminal: %q", p.shown())
	}
	after := p.termios()
	if after.Lflag != p.orig.Lflag || after.Iflag != p.orig.Iflag || after.Oflag != p.orig.Oflag || after.Cflag != p.orig.Cflag {
		t.Errorf("terminal state not restored after a normal return:\n before %+v\n after  %+v", p.orig, after)
	}
	if code := p.finish(); code != 0 {
		t.Errorf("child exit code %d", code)
	}
}

func TestPTYReadPasswordCRLFAndPartialLine(t *testing.T) {
	// A typed Enter arrives as CR (ICRNL turns it into the newline readLine wants).
	p := startChild(t, true)
	p.waitPrompt()
	p.type_("pa ss\r")
	if got, want := p.result(), `"pa ss" <nil>`; got != want {
		t.Fatalf("ReadPassword returned %s, want %s", got, want)
	}
	p.finish()
}

func TestPTYReadPasswordEOF(t *testing.T) {
	const eof = "\x04" // Ctrl-D at the start of a line
	t.Run("empty line", func(t *testing.T) {
		p := startChild(t, true)
		p.waitPrompt()
		p.type_(eof)
		if got, want := p.result(), `"" EOF`; got != want {
			t.Fatalf("ReadPassword returned %s, want %s", got, want)
		}
		if after := p.termios(); after.Lflag != p.orig.Lflag {
			t.Errorf("echo not restored after EOF: lflag %#x, was %#x", after.Lflag, p.orig.Lflag)
		}
		p.finish()
	})
	t.Run("after text", func(t *testing.T) {
		// The first Ctrl-D flushes "abc" to the reader without a newline; the second, on
		// the now-empty line, is EOF. What was typed is returned, not dropped.
		p := startChild(t, true)
		p.waitPrompt()
		p.type_("abc" + eof)
		time.Sleep(50 * time.Millisecond) // let the reader consume the flushed bytes before the second EOF
		p.type_(eof)
		if got, want := p.result(), `"abc" <nil>`; got != want {
			t.Fatalf("ReadPassword returned %s, want %s", got, want)
		}
		p.finish()
	})
}

// typeLine types n bytes and Enter, in pieces so the tty's input queue never has to hold
// more than the reader has not yet consumed.
func (p *ptyChild) typeLine(n int) {
	p.t.Helper()
	for ; n > 0; n -= 256 {
		p.type_(strings.Repeat("x", min(n, 256)))
		time.Sleep(20 * time.Millisecond)
	}
	p.type_("\n")
}

// MaxLen is 1024, which is also macOS's canonical line limit: the kernel rings the bell
// and drops what does not fit, so a longer line (or even a 1024-byte one with its
// newline) never reaches ReadPassword there. The cases that need more than the kernel
// delivers skip on seeing the bell; the others run everywhere.
func TestPTYReadPasswordLengths(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
		want string // the child's result line
	}{
		{"one under the limit", MaxLen - 1, fmt.Sprintf("%q <nil>", strings.Repeat("x", MaxLen-1))},
		{"at the limit", MaxLen, fmt.Sprintf("%q <nil>", strings.Repeat("x", MaxLen))},
		{"one over the limit", MaxLen + 1, `"" keystore: passphrase too long`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := startChild(t, true)
			p.waitPrompt()
			p.typeLine(tc.n)
			var got string
			select {
			case got = <-p.lines:
			case <-time.After(time.Second):
				if strings.Contains(p.shown(), "\a") {
					t.Skip("the kernel's line limit dropped the excess (bell); see the test comment")
				}
				t.Fatalf("no result; terminal showed %.80q", p.shown())
			}
			if got != tc.want {
				t.Fatalf("ReadPassword returned %.80s, want %.80s", got, tc.want)
			}
			if after := p.termios(); after.Lflag != p.orig.Lflag {
				t.Errorf("echo not restored: lflag %#x, was %#x", after.Lflag, p.orig.Lflag)
			}
			p.finish()
		})
	}
}

func TestPTYNoControllingTerminal(t *testing.T) {
	p := startChild(t, false)
	if got, want := p.result(), fmt.Sprintf("%q %v", "", ErrNoTTY); got != want {
		t.Fatalf("ReadPassword returned %s, want %s", got, want)
	}
	p.finish()
}

// End to end counterpart of TestInterruptRestoresTerminalAndExits: the process really
// dies with 130 and the user's terminal really gets its echo back.
func TestPTYSignalRestoresEchoAndExits130(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			p := startChild(t, true)
			p.waitPrompt()
			if echoOn(p.termios()) {
				t.Fatal("echo is ON while the prompt waits")
			}
			if err := p.cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			if code := p.wait(); code != 130 {
				t.Errorf("exit code %d, want 130", code)
			}
			after := p.termios()
			if after.Lflag != p.orig.Lflag || after.Iflag != p.orig.Iflag {
				t.Errorf("terminal left changed after %v:\n before %+v\n after  %+v", sig, p.orig, after)
			}
			if strings.Contains(p.shown(), "goroutine ") {
				t.Errorf("%v dumped a Go traceback to the terminal: %q", sig, p.shown())
			}
		})
	}
}
