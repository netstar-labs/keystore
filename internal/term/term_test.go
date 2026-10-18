package term

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func TestIsTerminalOnRegularFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if IsTerminal(f.Fd()) {
		t.Fatal("a regular file reported as a terminal")
	}
}

func TestReadLine(t *testing.T) {
	r, w, _ := os.Pipe()
	w.WriteString("secret\r\nnext")
	w.Close()
	got, err := readLine(r)
	if err != nil || string(got) != "secret" {
		t.Fatalf("readLine = %q, %v", got, err)
	}
	rest, _ := readLine(r)
	if string(rest) != "next" {
		t.Fatalf("readLine consumed past the newline: %q", rest)
	}
}

func TestReadLineTooLong(t *testing.T) {
	r, w, _ := os.Pipe()
	go func() {
		w.Write(make([]byte, MaxLen+10))
		w.Close()
	}()
	if _, err := readLine(r); err == nil {
		t.Fatal("over-long line accepted")
	}
}

// Ctrl-\ (SIGQUIT) and the hangup of a closing terminal used to bypass the terminal
// restore: the shell was left without echo (and Ctrl-\ also dumped a Go traceback).
func TestInterruptRestoresTerminalAndExits(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			restored := make(chan struct{})
			exited := make(chan int, 1)
			stop := restoreOnSignal(func() { close(restored) }, func(code int) { exited <- code })
			defer stop()
			if err := syscall.Kill(os.Getpid(), sig); err != nil {
				t.Fatal(err)
			}
			select {
			case code := <-exited:
				select {
				case <-restored:
				default:
					t.Fatal("exited without restoring the terminal first")
				}
				if code != 130 {
					t.Errorf("exit code %d, want 130", code)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("%v during the prompt was not handled", sig)
			}
		})
	}
}

func TestStopWatchingIgnoresLaterSignals(t *testing.T) {
	exited := make(chan int, 1)
	stop := restoreOnSignal(func() {}, func(code int) { exited <- code })
	stop()
	// with the watcher stopped, SIGHUP must not call exit (the process keeps default
	// handling off: keep a Notify so the test process itself does not die)
	keep := make(chan os.Signal, 1)
	signal.Notify(keep, syscall.SIGHUP)
	defer signal.Stop(keep)
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	select {
	case <-keep:
	case <-time.After(time.Second):
		t.Fatal("test signal not delivered")
	}
	select {
	case code := <-exited:
		t.Fatalf("exit(%d) called after stop", code)
	case <-time.After(100 * time.Millisecond):
	}
}
