//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// These tests are hermetic (a fake runner, no container, no KEYSTORE_LIVE): they pin the
// skip-vs-fail rule itself.

type call struct {
	out  string
	exit int
	err  error
}

type fakeRunner struct {
	noBinary bool
	byCmd    map[string]call // keyed by the joined command line
}

func (f fakeRunner) LookPath(file string) (string, error) {
	if f.noBinary {
		return "", errors.New("executable file not found in $PATH")
	}
	return "/usr/local/bin/" + file, nil
}

func (f fakeRunner) Run(_ context.Context, name string, args ...string) (string, int, error) {
	c, ok := f.byCmd[name+" "+strings.Join(args, " ")]
	if !ok {
		return "", 0, errors.New("unexpected command")
	}
	return c.out, c.exit, c.err
}

func TestPreflightUnreachableRuntimeSkips(t *testing.T) {
	ctx := context.Background()
	ok := map[string]call{"container system status": {out: "status running"}}
	for _, tc := range []struct {
		name string
		r    fakeRunner
		want string // substring of the skip reason; "" = usable
	}{
		{"no binary", fakeRunner{noBinary: true}, "not installed"},
		{"system stopped", fakeRunner{byCmd: map[string]call{"container system status": {out: "not running", exit: 1}}}, "not running"},
		{"status cannot start", fakeRunner{byCmd: map[string]call{"container system status": {err: errors.New("fork failed")}}}, "not running"},
		{"usable", fakeRunner{byCmd: ok}, ""},
	} {
		got := preflight(ctx, tc.r)
		if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
			t.Errorf("%s: preflight = %q, want substring %q", tc.name, got, tc.want)
		}
	}
}

func TestImageMissingSkips(t *testing.T) {
	r := fakeRunner{byCmd: map[string]call{
		"container image inspect alpine:latest": {out: "ok"},
		"container image inspect nope:1":        {out: "Error: not found", exit: 1},
	}}
	if got := imageReason(context.Background(), r, "alpine:latest"); got != "" {
		t.Errorf("present image: %q", got)
	}
	if got := imageReason(context.Background(), r, "nope:1"); !strings.Contains(got, "not present") {
		t.Errorf("missing image: %q", got)
	}
}

// stream builds the marker stream inside.sh prints for pkgs packages under the given uids;
// passing is each package's passing-test count.
func stream(pkgs int, uids []string, passing int) string {
	var b strings.Builder
	b.WriteString("KSL3 BEGIN x\n")
	for _, uid := range uids {
		for i := 0; i < pkgs; i++ {
			fmt.Fprintf(&b, "KSL3 RESULT uid=%s pkg=p%d rc=0\nKSL3 COUNTS uid=%s pkg=p%d pass=%d skip=0 fail=0\n", uid, i, uid, i, passing)
		}
	}
	b.WriteString("KSL3 DONE\n")
	return b.String()
}

func TestClassifyRun(t *testing.T) {
	both := []string{"0", "1000"}
	good := stream(2, both, 3)
	for _, tc := range []struct {
		name string
		out  string
		exit int
		err  error
		want int // packages staged
		v    verdict
		sub  string
	}{
		{"all pass", good, 0, nil, 2, pass, ""},
		{"container never ran our script", "Error: image not found\n", 1, nil, 2, skip, "before the keystore run began"},
		{"could not start", "", 0, errors.New("xpc connection invalid"), 2, skip, "did not start"},
		{"install failed", "KSL3 BEGIN x\nKSL3 SKIP cannot install openssl\n", 77, nil, 2, skip, "cannot install openssl"},
		{"exit 77 alone", "KSL3 BEGIN x\n", 77, nil, 2, skip, "prerequisites"},
		{"a test's own indented output cannot fake a skip", "KSL3 BEGIN x\n  KSL3 SKIP pretend\n" + strings.TrimPrefix(good, "KSL3 BEGIN x\n"), 0, nil, 2, pass, ""},
		{"keystore test failed", "KSL3 BEGIN x\nKSL3 RESULT uid=0 pkg=pkg/agent rc=1\nKSL3 DONE\n", 1, nil, 2, fail, "pkg/agent"},
		{"failure wins over install note", "KSL3 BEGIN x\nKSL3 RESULT uid=0 pkg=a rc=2\nKSL3 DONE\n", 0, nil, 2, fail, "rc=2"},
		{"died midway", "KSL3 BEGIN x\nKSL3 RESULT uid=0 pkg=a rc=0\n", 137, nil, 2, fail, "without"},
		{"hang after begin", "KSL3 BEGIN x\n", 0, context.DeadlineExceeded, 2, fail, "did not finish"},
		{"clean results, bad exit", good, 3, nil, 2, fail, "exited 3"},
		// vacuous-pass guards: a run that reports less than was staged must not pass
		{"empty manifest", stream(0, both, 3), 0, nil, 0, fail, "empty"},
		{"manifest line eaten by a test reading stdin", stream(1, both, 3), 0, nil, 2, fail, "want 2"},
		{"uid 1000 leg missing", stream(2, []string{"0"}, 3), 0, nil, 2, fail, "uid 1000 reported 0"},
		{"uid 0 leg missing", stream(2, []string{"1000"}, 3), 0, nil, 2, fail, "uid 0 reported 0"},
		{"extra unexpected package", stream(3, both, 3), 0, nil, 2, fail, "want 2"},
		{"every test skipped", stream(2, both, 0), 0, nil, 2, fail, "only skipped"},
	} {
		v, why := classifyRun(tc.out, tc.exit, tc.err, tc.want)
		if v != tc.v || !strings.Contains(why, tc.sub) {
			t.Errorf("%s: got %v %q, want %v containing %q", tc.name, v, why, tc.v, tc.sub)
		}
	}
}

// The real runner must report a deadline as the context's error (exec.CommandContext alone
// yields an ExitError with exit -1), because classifyRun treats that as a hang.
func TestExecRunnerReportsDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, _, err := (execRunner{}).Run(ctx, "sleep", "5"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if _, exit, err := (execRunner{}).Run(context.Background(), "sh", "-c", "exit 3"); err != nil || exit != 3 {
		t.Fatalf("plain nonzero exit: exit=%d err=%v, want 3 and nil", exit, err)
	}
}

// inside.sh feeds its manifest to a loop that runs the test binaries; a binary that reads
// stdin must not be able to consume manifest lines. Pin both defences textually (the
// behavioural guard is the exact-count check in classifyRun above).
func TestInsideScriptIsolatesStdin(t *testing.T) {
	s := string(insideSh)
	if !strings.Contains(s, "</dev/null 2>&1)") {
		t.Error("the test-binary invocation no longer has </dev/null")
	}
	if !strings.Contains(s, "<&3") || !strings.Contains(s, `3<"$KS/manifest"`) {
		t.Error("the manifest is no longer read on its own descriptor")
	}
}
