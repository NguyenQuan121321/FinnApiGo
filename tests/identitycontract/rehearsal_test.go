package identitycontract

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// Offline safety/HTTP-contract orchestration only; no deployed acceptance claim.
func TestF02RehearsalTool(t *testing.T) {
	python := "python3"
	if runtime.GOOS == "windows" {
		python = "python"
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate fixed rehearsal test directory")
	}
	cmd := exec.Command(python, "-B", "-m", "unittest", "-v", "test_rehearsal.py") // #nosec G204 -- fixed interpreter, arguments and repository test directory.
	cmd.Dir = filepath.Dir(source)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("offline rehearsal tests: %v\n%s", err, output)
	}
	t.Log(string(output))
}
