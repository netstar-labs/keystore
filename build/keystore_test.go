package build

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// These tests run the real build/keystore script in a throwaway git repo holding a
// one-line stub CLI: the version stamp and the dirty-tree rule are properties of the
// script, not of the keystore sources.

func run(t *testing.T, dir string, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// repo returns a clean, tagged copy of the build inputs.
func repo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, data []byte) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"build/keystore", ".gitignore"} {
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		write(f, b)
	}
	for _, f := range []string{"README.md", "SECURITY.md", "THIRD-PARTY-NOTICES"} {
		write(f, []byte("x\n"))
	}
	write("go.mod", []byte("module stub\n\ngo 1.27.0\n"))
	write("cmd/keystore/main.go", []byte("package main\n\nvar version, build string\n\nfunc main() {}\n"))
	for _, c := range [][]string{
		{"init", "-q"}, {"add", "-A"}, {"commit", "-q", "-m", "init"}, {"tag", "v1.0.0"},
	} {
		if out, err := run(t, dir, "git", c...); err != nil {
			t.Fatalf("git %v: %v\n%s", c, err, out)
		}
	}
	return dir
}

func archives(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, "build/install/release/keystore-*.tgz"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestReleaseCleanTree(t *testing.T) {
	dir := repo(t)
	out, err := run(t, dir, "build/keystore", "--release")
	if err != nil {
		t.Fatalf("clean release failed: %v\n%s", err, out)
	}
	got := archives(t, dir)
	if len(got) != 4 {
		t.Fatalf("want 4 archives, got %v\n%s", got, out)
	}
	for _, a := range got {
		// exactly the tag: no -N-gSHA suffix from describe
		if !regexp.MustCompile(`/keystore-v1\.0\.0-(linux|darwin)-(amd64|arm64)\.tgz$`).MatchString(a) {
			t.Errorf("archive %s: want a clean v1.0.0 name", a)
		}
	}
}

// A release from a dirty tree would be named like a clean one while -buildvcs bakes
// vcs.modified=true into the binary; it must be refused, for tracked changes and for
// untracked files alike (Go counts both).
func TestReleaseRefusesDirtyTree(t *testing.T) {
	for name, dirty := range map[string]func(string) error{
		"untracked": func(d string) error { return os.WriteFile(filepath.Join(d, "bin"), []byte("x"), 0o644) },
		"modified":  func(d string) error { return os.WriteFile(filepath.Join(d, "README.md"), []byte("y\n"), 0o644) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := repo(t)
			if err := dirty(dir); err != nil {
				t.Fatal(err)
			}
			out, err := run(t, dir, "build/keystore", "--release")
			if err == nil {
				t.Fatalf("dirty release succeeded:\n%s", out)
			}
			if got := archives(t, dir); len(got) != 0 {
				t.Fatalf("dirty release left archives %v", got)
			}
			if !strings.Contains(out, "dirty") {
				t.Errorf("refusal does not say why:\n%s", out)
			}
		})
	}
}

// A release must be built from exactly a tag: a clean HEAD past the tag would be named
// keystore-v1.0.0-1-gSHA, and with no reachable tag at all, "dev". The same refusal
// covers a tag that sits on an older commit.
func TestReleaseRefusesUntaggedHead(t *testing.T) {
	dir := repo(t)
	if out, err := run(t, dir, "git", "commit", "-q", "--allow-empty", "-m", "after the tag"); err != nil {
		t.Fatalf("commit: %v\n%s", err, out)
	}
	out, err := run(t, dir, "build/keystore", "--release")
	if err == nil {
		t.Fatalf("release from an untagged HEAD succeeded:\n%s", out)
	}
	if got := archives(t, dir); len(got) != 0 {
		t.Fatalf("untagged release left archives %v", got)
	}
	if !strings.Contains(out, "git tag") {
		t.Errorf("refusal does not say how to tag first:\n%s", out)
	}
	// dev builds are unchanged: still stamped with the describe suffix
	out, err = run(t, dir, "build/keystore")
	if err != nil || !strings.Contains(out, "VERSION  v1.0.0-1-g") {
		t.Fatalf("dev build from an untagged HEAD changed: %v\n%s", err, out)
	}
}

// CI checks a tag out detached; that is the normal release path.
func TestReleaseDetachedHeadOnTag(t *testing.T) {
	dir := repo(t)
	if out, err := run(t, dir, "git", "checkout", "-q", "--detach", "v1.0.0"); err != nil {
		t.Fatalf("checkout: %v\n%s", err, out)
	}
	out, err := run(t, dir, "build/keystore", "--release")
	if err != nil {
		t.Fatalf("detached release on the tag failed: %v\n%s", err, out)
	}
	if got := archives(t, dir); len(got) != 4 {
		t.Fatalf("want 4 archives, got %v\n%s", got, out)
	}
}

// Dev builds on a dirty tree proceed, but are stamped.
func TestDevBuildStampsDirty(t *testing.T) {
	dir := repo(t)
	if err := os.WriteFile(filepath.Join(dir, "bin"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, dir, "build/keystore")
	if err != nil {
		t.Fatalf("dev build failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "VERSION  v1.0.0-dirty ") {
		t.Fatalf("dev build on a dirty tree not stamped -dirty:\n%s", out)
	}
}
