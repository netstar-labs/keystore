//go:build topology

package topology

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// exchange connects to sock and sends a raw `P` frame, bypassing the client library (whose
// own check that the server runs as the current user would refuse first). It reports
// whether connect succeeded and how many reply bytes came back before the connection ended.
func exchange(sock string) string {
	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return "connect-error=" + errString(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte{'P', 0, 0, 0, 0}); err != nil {
		return "connected write-error=" + errString(err)
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, err := io.ReadAll(c)
	if len(b) > 0 {
		return fmt.Sprintf("connected reply-bytes=%d", len(b))
	}
	if err != nil {
		return "connected reply-bytes=0 err=" + errString(err)
	}
	return "connected reply-bytes=0 eof"
}

func errString(err error) string {
	switch {
	case errors.Is(err, syscall.EACCES):
		return "EACCES"
	case errors.Is(err, syscall.ECONNRESET):
		return "ECONNRESET"
	}
	return err.Error()
}

// helperMain is the body of a re-executed test binary used as a raw client under another
// uid (see TestCrossUID).
func helperMain() {
	fmt.Println(exchange(os.Getenv("TOPO_SOCK")))
}

func asUser(uid int, name string, env []string, args ...string) result {
	cmd := exec.Command(name, args...)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(uid)}}
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	r := result{stdout: so.String(), stderr: se.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		r.code = ee.ExitCode()
	} else if err != nil {
		r.code, r.stderr = -2, r.stderr+err.Error()
	}
	return r
}

// TestCrossUID runs inside a Linux container as root. The agent runs as uid 1000. The
// socket's mode is then made permissive on purpose (directory 0755, socket 0666), after a
// control that shows the default mode really does keep uid 1001 out, and a client as uid
// 1001, a client as root and a client as uid 1000 connect. Only uid 1000 may get a reply;
// the others are refused by the agent's peer-uid check: they CONNECT (so the mode is not
// what stopped them), the connection is closed with no reply, and the agent logs the
// rejected uid.
func TestCrossUID(t *testing.T) {
	need(t)
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("needs Linux and root (run it in the container: scripts/topology.sh container)")
	}
	const agentUID, otherUID = 1000, 1001
	base, err := os.MkdirTemp("", "xu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	os.Chmod(base, 0o755)
	home := filepath.Join(base, "h")
	os.Mkdir(home, 0o755)
	ring := filepath.Join(base, "r.ks")
	if r := ks(home, pass(0), "", "keygen", "-keystore", ring, "-id", "k1"); !r.ok() {
		t.Fatalf("keygen: %s", r.stderr)
	}
	os.Chown(ring, agentUID, agentUID)
	sd := filepath.Join(base, "s")
	os.Mkdir(sd, 0o700)
	os.Chown(sd, agentUID, agentUID)
	sock := filepath.Join(sd, "a.sock")

	log := &syncBuf{}
	cmd := exec.Command(bin("keystore-agent"), "-keystore", ring, "-sock", sock, "-ttl", "5m")
	cmd.Env = append(cleanEnv(home), "KEYSTORE_PASSPHRASE="+pass(0))
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: agentUID, Gid: agentUID}}
	cmd.Stderr, cmd.Stdout = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	// Wait for the socket file, not a dial: a dial here would be a root client the agent logs.
	for i := 0; ; i++ {
		if st, err := os.Lstat(sock); err == nil && st.Mode()&os.ModeSocket != 0 {
			break
		}
		if i > 400 {
			t.Fatalf("agent did not create its socket: %s", log.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)

	self, _ := os.Executable()
	helper := func(uid int) string {
		r := asUser(uid, self, append(cleanEnv(home), "TOPO_HELPER=rawclient", "TOPO_SOCK="+sock))
		return strings.TrimSpace(r.stdout + r.stderr)
	}

	// Control: with the default modes (dir 0700, socket 0600, owned by 1000) uid 1001 cannot
	// even connect, so loosening the mode below is what makes the test meaningful.
	ctl := helper(otherUID)
	t.Logf("control, default modes: uid %d: %s", otherUID, ctl)
	if !strings.Contains(ctl, "EACCES") {
		t.Errorf("control: uid %d with default modes got %q, want connect EACCES", otherUID, ctl)
	}

	// Make the path reachable by everyone.
	if err := os.Chmod(sd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sock, 0o666); err != nil {
		t.Fatal(err)
	}
	dst, _ := os.Stat(sd)
	sst, _ := os.Stat(sock)
	t.Logf("permissive: dir %v socket %v", dst.Mode(), sst.Mode())

	same := helper(agentUID)
	other := helper(otherUID)
	root := exchange(sock) // this test process is root
	t.Logf("uid %d (agent's own):  %s", agentUID, same)
	t.Logf("uid %d (other user):   %s", otherUID, other)
	t.Logf("uid 0    (root):         %s", root)
	if same != "connected reply-bytes=37" {
		t.Errorf("same-uid client: %q, want a 37-byte public-key reply", same)
	}
	for name, got := range map[string]string{"uid 1001": other, "root": root} {
		if !strings.HasPrefix(got, "connected reply-bytes=0") {
			t.Errorf("%s: %q; want connected (mode permits) and then closed with no reply (peer-uid refusal)", name, got)
		}
	}

	// Real CLI clients. Their own library also refuses a server of another uid (client-side
	// peer check); same uid must work end to end.
	msgFile := filepath.Join(base, "msg")
	os.WriteFile(msgFile, []byte("cross-uid"), 0o644)
	cli := func(uid int) result {
		return asUser(uid, bin("keystore"), cleanEnv(home), "sign", "-agent", sock, "-in", msgFile)
	}
	if r := cli(agentUID); r.code != 0 {
		t.Errorf("keystore sign -agent as uid %d: %+v", agentUID, r)
	}
	for _, uid := range []int{otherUID, 0} {
		r := cli(uid)
		if r.code == 0 || !strings.Contains(r.stderr, "not the current user") {
			t.Errorf("keystore sign -agent as uid %d: want refusal 'not the current user', got code=%d %q", uid, r.code, r.stderr)
		}
	}

	// The agent's own record of who it refused.
	time.Sleep(200 * time.Millisecond)
	lg := log.String()
	t.Logf("agent log:\n%s", lg)
	for _, want := range []string{"rejected connection: peer uid 1001 (want 1000)", "rejected connection: peer uid 0 (want 1000)"} {
		if !strings.Contains(lg, want) {
			t.Errorf("agent log lacks %q", want)
		}
	}
	if strings.Contains(lg, "peer uid 1000") {
		t.Errorf("the agent rejected its own uid")
	}
	record("cross-uid", map[string]any{"control_default_mode": ctl, "same_uid": same, "other_uid": other, "root": root,
		"dir_mode": dst.Mode().String(), "sock_mode": sst.Mode().String()})
}
