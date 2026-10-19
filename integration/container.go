//go:build integration

// Package integration is the host side of the live-integration tier (audit L3): it
// cross-compiles keystore for Linux and runs the whole suite inside an Apple `container`.
// This file is the skip-vs-fail classifier. The rule it enforces: a problem with the
// environment (no runtime, runtime not started, image missing, dependencies that could
// not be installed, the container never reached the keystore code) SKIPs with a reason;
// only something keystore itself did (a failing test, a build error, a hang) FAILs.
package integration

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// runner is the seam the classifier is tested through: the real one shells out, the test
// one is a fake.
type runner interface {
	LookPath(file string) (string, error)
	// Run returns combined output and the exit status; err is set only when the command
	// could not be started or the context ended.
	Run(ctx context.Context, name string, args ...string) (out string, exit int, err error)
}

type execRunner struct{}

func (execRunner) LookPath(f string) (string, error) { return exec.LookPath(f) }

func (execRunner) Run(ctx context.Context, name string, args ...string) (string, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	// A deadline kills the process, which surfaces as an ExitError (exit -1); report the
	// context's error instead so callers can tell "ran out of time" from "exited nonzero".
	if cerr := ctx.Err(); cerr != nil {
		return string(out), 0, cerr
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return string(out), ee.ExitCode(), nil
	}
	return string(out), 0, err
}

// preflight returns "" when the container runtime is usable, else the reason to skip.
func preflight(ctx context.Context, r runner) string {
	if _, err := r.LookPath("container"); err != nil {
		return "the `container` CLI is not installed (Apple container): " + err.Error()
	}
	if out, exit, err := r.Run(ctx, "container", "system", "status"); err != nil || exit != 0 {
		return "the container system is not running (try `container system start`): " + firstLine(out, err)
	}
	return ""
}

// imageReason returns "" when image is present locally, else the reason to skip that image.
// It never pulls: fetching is the operator's decision.
func imageReason(ctx context.Context, r runner, image string) string {
	if out, exit, err := r.Run(ctx, "container", "image", "inspect", image); err != nil || exit != 0 {
		return fmt.Sprintf("image %s is not present locally (`container image pull %s`): %s", image, image, firstLine(out, err))
	}
	return ""
}

func firstLine(out string, err error) string {
	if err != nil {
		return err.Error()
	}
	s := strings.TrimSpace(out)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

type verdict int

const (
	pass verdict = iota
	skip
	fail
)

func (v verdict) String() string { return [...]string{"pass", "skip", "fail"}[v] }

// Markers printed by container/inside.sh. KSL3 BEGIN proves the script (and so keystore's
// side of the run) started; KSL3 DONE proves it ran to the end.
const (
	markBegin  = "KSL3 BEGIN"
	markDone   = "KSL3 DONE"
	markResult = "KSL3 RESULT "
	markCounts = "KSL3 COUNTS "
	markSkip   = "KSL3 SKIP "
	exitSkip   = 77 // inside.sh: a prerequisite (package install) was unavailable
)

// legUIDs are the identities inside.sh runs every package as.
var legUIDs = []string{"0", "1000"}

// classifyRun turns one container run into a verdict. want is the number of test binaries
// the host staged (the manifest length): the run must report every one of them, for every
// uid, so a shortened or empty run cannot pass by omission.
//
//   - runErr != nil (could not start, or the deadline hit): started-but-never-BEGIN is an
//     environment problem (skip); a deadline after BEGIN is a hang in the run, which fails.
//   - no BEGIN marker: the container never reached our script (image/VM/mount problem): skip.
//   - exit 77 or a KSL3 SKIP line: prerequisites unavailable: skip.
//   - any RESULT line with rc != 0: a keystore test failed: fail.
//   - BEGIN but no DONE: the run died midway; fail rather than hide a crash or hang.
//   - not exactly want RESULT rc=0 lines per uid, or a package that passed no test at all
//     (every test skipped): fail. A skipped test is not a passed one.
//   - otherwise pass.
func classifyRun(out string, exit int, runErr error, want int) (verdict, string) {
	lines := strings.Split(out, "\n")
	began := hasLine(lines, markBegin)
	if runErr != nil {
		if !began {
			return skip, "container did not start the run: " + runErr.Error()
		}
		return fail, "run did not finish: " + runErr.Error()
	}
	if !began {
		return skip, fmt.Sprintf("container exited %d before the keystore run began: %s", exit, firstLine(out, nil))
	}
	if exit == exitSkip || hasLine(lines, markSkip) {
		return skip, skipReason(lines)
	}
	var bad []string
	ok := map[string]int{}      // uid -> RESULT lines with rc=0
	passing := map[string]int{} // uid -> COUNTS lines with pass>0
	for _, l := range lines {
		if rest, found := strings.CutPrefix(l, markResult); found {
			if strings.HasSuffix(rest, " rc=0") {
				ok[uidOf(rest)]++
			} else {
				bad = append(bad, rest)
			}
		}
		if rest, found := strings.CutPrefix(l, markCounts); found && !strings.Contains(rest, " pass=0 ") {
			passing[uidOf(rest)]++
		}
	}
	if len(bad) > 0 {
		return fail, "failing: " + strings.Join(bad, "; ")
	}
	if !hasLine(lines, markDone) {
		return fail, fmt.Sprintf("run ended without %q (exit %d)", markDone, exit)
	}
	if exit != 0 {
		return fail, fmt.Sprintf("all results passed but the script exited %d", exit)
	}
	if want <= 0 {
		return fail, "the staged manifest is empty: nothing was run"
	}
	for _, uid := range legUIDs {
		if ok[uid] != want {
			return fail, fmt.Sprintf("uid %s reported %d passing packages, want %d (a leg or a package went missing)", uid, ok[uid], want)
		}
		if passing[uid] != want {
			return fail, fmt.Sprintf("uid %s: %d of %d packages passed at least one test (the rest only skipped)", uid, passing[uid], want)
		}
	}
	return pass, ""
}

// uidOf extracts N from a "uid=N pkg=..." marker payload.
func uidOf(rest string) string {
	rest = strings.TrimPrefix(rest, "uid=")
	uid, _, _ := strings.Cut(rest, " ")
	return uid
}

func hasLine(lines []string, prefix string) bool {
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

func skipReason(lines []string) string {
	for _, l := range lines {
		if rest, ok := strings.CutPrefix(l, markSkip); ok {
			return rest
		}
	}
	return "prerequisites unavailable in the container"
}
