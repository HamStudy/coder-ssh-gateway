// Package testutil hosts the Go-side helpers for the fake-coder test
// harness: building the fake binary once per test run, constructing the
// §18.3 allowlist environment, and parsing FAKE_CODER_RECORD output.
//
// The fake binary itself lives in internal/testutil/fake-coder behind the
// "fakecoder" build tag so that plain `go build ./...` never compiles it.
package testutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
)

var (
	fakeBuildOnce sync.Once
	fakeBuildPath string
	fakeBuildErr  error
)

// BuildFakeCoder compiles the fake-coder test binary exactly once per test
// process into a shared temporary directory and returns its path. The build
// is cached across all tests in the run, so calling it from many tests is
// cheap. The binary is TEST-ONLY and never shipped.
func BuildFakeCoder(t testing.TB) string {
	t.Helper()
	fakeBuildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "coder-ssh-gateway-fake-coder")
		if err != nil {
			fakeBuildErr = err
			return
		}
		out := filepath.Join(dir, "fake-coder")

		// Resolve the repo root relative to this source file so the build
		// works regardless of the test binary's working directory.
		_, src, _, ok := runtime.Caller(0)
		if !ok {
			fakeBuildErr = errString("runtime.Caller failed")
			return
		}
		repoRoot := filepath.Clean(filepath.Join(filepath.Dir(src), "..", ".."))

		cmd := exec.Command("go", "build", "-tags", "fakecoder", "-o", out, "./internal/testutil/fake-coder/")
		cmd.Dir = repoRoot
		if combined, err := cmd.CombinedOutput(); err != nil {
			fakeBuildErr = errString("go build fake-coder: " + err.Error() + "\n" + string(combined))
			return
		}
		fakeBuildPath = out
	})
	if fakeBuildErr != nil {
		t.Fatalf("BuildFakeCoder: %v", fakeBuildErr)
	}
	return fakeBuildPath
}

// FakeEnv returns the §18.3 allowlist environment for spawning the fake (or
// real) coder binary in tests: a fixed minimal PATH/HOME/TMPDIR plus the
// approved CODER_* variables carrying the given session token. Tests add
// FAKE_CODER_* knobs or poison variables on top of this slice.
func FakeEnv(token string) []string {
	return []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=/var/empty/coder-ssh-gateway",
		"TMPDIR=/tmp/coder-ssh-gateway",
		"CODER_URL=https://coder.example.com",
		"CODER_SESSION_TOKEN=" + token,
		"CODER_NO_VERSION_WARNING=true",
		"CODER_NO_FEATURE_WARNING=true",
		"CODER_DISABLE_NETWORK_TELEMETRY=true",
	}
}

// FakeArgv returns the canonical §18.2 argv the gateway builds for a
// transport tunnel. Tests mutate copies of it to exercise the fake's
// contract checks.
func FakeArgv(globalConfigDir, waitMode, target string, disableAutostart bool) []string {
	args := []string{
		"--global-config", globalConfigDir,
		"ssh",
		"--stdio",
		"--wait=" + waitMode,
	}
	if disableAutostart {
		args = append(args, "--disable-autostart=true")
	}
	return append(args, target)
}

// FakeRecord is one JSON line appended by the fake binary to the file named
// by FAKE_CODER_RECORD. It intentionally carries env KEY names and the
// token LENGTH only — never any secret value.
type FakeRecord struct {
	Argv        []string `json:"argv"`
	EnvKeys     []string `json:"env_keys"`
	TokenLength int      `json:"token_length"`
}

// ReadFakeRecords parses every JSON line of a FAKE_CODER_RECORD file.
func ReadFakeRecords(t testing.TB, path string) []FakeRecord {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFakeRecords: %v", err)
	}
	var records []FakeRecord
	for i, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r FakeRecord
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("ReadFakeRecords: line %d: %v", i+1, err)
		}
		records = append(records, r)
	}
	return records
}

// NewFakeCmd prepares an exec.Cmd for the fake binary in its own process
// group (Setpgid, mirroring §19.4) and registers a t.Cleanup that SIGKILLs
// the whole group, so grandchildren (FAKE_CODER_SPAWN_CHILD) cannot leak.
// The caller wires stdin/stdout/stderr and calls Start or Run.
func NewFakeCmd(t testing.TB, bin string, env []string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	t.Cleanup(func() {
		if cmd.Process == nil {
			return
		}
		// Negative PID targets the process group; ESRCH on an already-reaped
		// process is expected and ignored.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	})
	return cmd
}

// WaitReaped waits for cmd and returns its exit code. A process killed by
// the cleanup path reports -1. It never fails the test; assertions on exit
// codes belong to the caller.
func WaitReaped(cmd *exec.Cmd) int {
	err := cmd.Wait()
	if err == nil {
		return 0
	}
	ee, ok := errors.AsType[*exec.ExitError](err)
	if ok {
		return ee.ExitCode()
	}
	return -1
}

type errString string

func (e errString) Error() string { return string(e) }
