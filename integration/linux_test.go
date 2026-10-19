//go:build integration

package integration

import (
	"context"
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netstar-labs/keystore/integration/internal/livetest"
)

//go:embed container/inside.sh
var insideSh []byte

// The shim stands in for the Go toolchain, which the images do not have: the example
// scripts run `go build -o DIR/ ./cmd/keystore ./cmd/keystore-agent` and
// `go run ./examples/NAME ARGS`, so the shim copies / execs the prebuilt linux binaries.
const goShim = `#!/bin/sh
case "$1" in
build)
    shift; out=
    while [ $# -gt 0 ]; do case "$1" in -o) out=$2; shift;; esac; shift; done
    cp /opt/ks/bin/keystore /opt/ks/bin/keystore-agent "$out" ;;
run)
    n=$(basename "$2"); shift 2; exec "/opt/ks/bin/ex-$n" "$@" ;;
*) echo "go shim: unsupported: $*" >&2; exit 2 ;;
esac
`

// images the Linux tier runs, in order. Both must already be present locally.
var images = []string{"alpine:latest", "debian:trixie-slim"}

// goCmd runs the host go tool in dir with a Linux/arm64 static build environment.
func goCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out) // a build error is the module's
	}
	return string(out)
}

// buildStage cross-compiles everything the container needs into a fresh directory and
// returns it with the manifest of test binaries.
func buildStage(t *testing.T, root string) string {
	t.Helper()
	stage, err := os.MkdirTemp("", "ksl3-") // not t.TempDir: it must be a short path the VM can mount
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(stage) })
	if err := os.Chmod(stage, 0o755); err != nil { // uid 1000 in the container must traverse it
		t.Fatal(err)
	}
	for _, d := range []string{"bin", "shim", "tests"} {
		if err := os.Mkdir(filepath.Join(stage, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(stage, "bin")
	goCmd(t, root, "build", "-trimpath", "-o", bin+"/", "./cmd/keystore", "./cmd/keystore-agent")
	for _, ex := range []string{"secrets", "signed-requests"} {
		goCmd(t, root, "build", "-trimpath", "-o", filepath.Join(bin, "ex-"+ex), "./examples/"+ex)
	}
	must := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(stage, name), b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	must("shim/go", []byte(goShim))
	must("inside.sh", insideSh)

	// Every package with tests, plus the two live packages built with the tag. The root
	// ./integration package is excluded: it is this driver.
	type set struct {
		tags string
		pats []string
	}
	var manifest strings.Builder
	for _, s := range []set{{"", []string{"./cmd/...", "./internal/...", "./pkg/...", "./examples/..."}}, {"integration", []string{"./integration/interop", "./integration/linuxlive"}}} {
		args := []string{"list"}
		if s.tags != "" {
			args = append(args, "-tags", s.tags)
		}
		args = append(args, "-f", "{{if or .TestGoFiles .XTestGoFiles}}{{.Dir}}{{end}}")
		for _, d := range strings.Fields(goCmd(t, root, append(args, s.pats...)...)) {
			rel, err := filepath.Rel(root, d)
			if err != nil {
				t.Fatal(err)
			}
			name := strings.ReplaceAll(rel, "/", "__")
			c := []string{"test", "-c", "-trimpath"}
			if s.tags != "" {
				c = append(c, "-tags", s.tags)
			}
			goCmd(t, root, append(c, "-o", filepath.Join(stage, "tests", name+".test"), "./"+rel)...)
			manifest.WriteString(name + "\t" + rel + "\n")
		}
	}
	must("manifest", []byte(manifest.String()))
	return stage
}

// TestLinuxTier runs the whole suite, as root and as uid 1000, in each image.
func TestLinuxTier(t *testing.T) {
	livetest.RequireLive(t)
	ctx := context.Background()
	var r runner = execRunner{}
	if why := preflight(ctx, r); why != "" {
		t.Skip(why)
	}
	root := livetest.ModuleRoot(t)
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain on PATH: cannot cross-compile")
	}
	stage := buildStage(t, root)
	for _, img := range images {
		t.Run(strings.NewReplacer(":", "_", "/", "_").Replace(img), func(t *testing.T) {
			if why := imageReason(ctx, r, img); why != "" {
				t.Skip(why)
			}
			rctx, cancel := context.WithTimeout(ctx, 40*time.Minute)
			defer cancel()
			out, exit, err := r.Run(rctx, "container", "run", "--rm", "-m", "2g", "-c", "4",
				"-v", stage+":/opt/ks:ro", "-v", root+":/src:ro", img, "sh", "/opt/ks/inside.sh")
			v, why := classifyRun(out, exit, err)
			for _, l := range strings.Split(out, "\n") {
				if strings.HasPrefix(l, "KSL3 ") {
					t.Log(l)
				}
			}
			switch v {
			case skip:
				t.Skip(why)
			case fail:
				t.Fatalf("%s\n--- container output (tail) ---\n%s", why, tail(out, 120))
			}
		})
	}
}

func tail(s string, n int) string {
	l := strings.Split(s, "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}
