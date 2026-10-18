package cirelease_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestRunScript runs this example end to end, exactly as a reader would.
func TestRunScript(t *testing.T) {
	if testing.Short() {
		t.Skip("example scripts build binaries; skipped in -short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "bash", "run.sh").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ALL CHECKS PASSED") {
		t.Fatalf("run.sh: %v\n%s", err, out)
	}
}
