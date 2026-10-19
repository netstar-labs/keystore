//go:build integration

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
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

func TestClassifyRun(t *testing.T) {
	good := "KSL3 BEGIN x\nKSL3 RESULT uid=0 pkg=a rc=0\nKSL3 RESULT uid=1000 pkg=a rc=0\nKSL3 DONE\n"
	for _, tc := range []struct {
		name string
		out  string
		exit int
		err  error
		want verdict
		sub  string
	}{
		{"all pass", good, 0, nil, pass, ""},
		{"container never ran our script", "Error: image not found\n", 1, nil, skip, "before the keystore run began"},
		{"could not start", "", 0, errors.New("xpc connection invalid"), skip, "did not start"},
		{"install failed", "KSL3 BEGIN x\nKSL3 SKIP cannot install openssl\n", 77, nil, skip, "cannot install openssl"},
		{"exit 77 alone", "KSL3 BEGIN x\n", 77, nil, skip, "prerequisites"},
		{"keystore test failed", "KSL3 BEGIN x\nKSL3 RESULT uid=0 pkg=pkg/agent rc=1\nKSL3 DONE\n", 1, nil, fail, "pkg/agent"},
		{"failure wins over install note", "KSL3 BEGIN x\nKSL3 RESULT uid=0 pkg=a rc=2\nKSL3 DONE\n", 0, nil, fail, "rc=2"},
		{"died midway", "KSL3 BEGIN x\nKSL3 RESULT uid=0 pkg=a rc=0\n", 137, nil, fail, "without"},
		{"hang after begin", "KSL3 BEGIN x\n", 0, context.DeadlineExceeded, fail, "did not finish"},
		{"clean results, bad exit", good, 3, nil, fail, "exited 3"},
	} {
		v, why := classifyRun(tc.out, tc.exit, tc.err)
		if v != tc.want || !strings.Contains(why, tc.sub) {
			t.Errorf("%s: got %v %q, want %v containing %q", tc.name, v, why, tc.want, tc.sub)
		}
	}
}
