package testutil_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/taxilian/coder-ssh-gateway/internal/testleaks"
	"github.com/taxilian/coder-ssh-gateway/internal/testutil"
	"github.com/taxilian/coder-ssh-gateway/internal/testutil/innerssh"
	"golang.org/x/crypto/ssh"
)

const testToken = "test-session-token-0123456789abcdef"

func baseArgv() []string {
	return testutil.FakeArgv(
		"/tmp/fake-global-config",
		"auto",
		"examtools-docs",
		false,
	)
}

// runFake runs the fake to completion and returns (exitCode, stdout, stderr).
func runFake(t *testing.T, env []string, args []string) (int, string, string) {
	t.Helper()
	cmd := testutil.NewFakeCmd(t, testutil.BuildFakeCoder(t), env, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run fake: %v", err)
		}
		code = ee.ExitCode()
	}
	return code, stdout.String(), stderr.String()
}

func TestFakeCoderContract(t *testing.T) {
	defer testleaks.Verify(t)

	tests := []struct {
		name       string
		mutateArgs func([]string) []string
		extraEnv   []string
		dropEnv    string
		wantCode   int
		wantStderr string
	}{
		{
			name:     "valid argv, autostart enabled",
			extraEnv: []string{"FAKE_CODER_EXIT_AFTER_MS=1"},
			wantCode: 0,
		},
		{
			name: "valid argv, autostart disabled",
			mutateArgs: func(a []string) []string {
				return testutil.FakeArgv("/tmp/fake-global-config", "yes", "general", true)
			},
			extraEnv: []string{"FAKE_CODER_EXIT_AFTER_MS=1"},
			wantCode: 0,
		},
		{
			name:       "missing --stdio",
			mutateArgs: func(a []string) []string { a[3] = "--not-stdio"; return a },
			wantCode:   70,
			wantStderr: "--stdio",
		},
		{
			name:       "wrong subcommand",
			mutateArgs: func(a []string) []string { a[2] = "version"; return a },
			wantCode:   70,
			wantStderr: "ssh",
		},
		{
			name:       "invalid wait mode",
			mutateArgs: func(a []string) []string { a[4] = "--wait=sometimes"; return a },
			wantCode:   70,
			wantStderr: "--wait",
		},
		{
			name:       "missing global config flag",
			mutateArgs: func(a []string) []string { a[0] = "--config"; return a },
			wantCode:   70,
			wantStderr: "--global-config",
		},
		{
			name:       "token leaked into argv target",
			mutateArgs: func(a []string) []string { a[5] = testToken; return a },
			wantCode:   70,
			wantStderr: "token leaked",
		},
		{
			name:       "token missing from env",
			dropEnv:    "CODER_SESSION_TOKEN=",
			wantCode:   70,
			wantStderr: "CODER_SESSION_TOKEN",
		},
		{
			name:       "unexpected ambient CODER_ variable",
			extraEnv:   []string{"FAKE_CODER_EXIT_AFTER_MS=1", "CODER_EVIL_AMBIENT=1"},
			wantCode:   71,
			wantStderr: "CODER_EVIL_AMBIENT",
		},
		{
			name:     "TLS client prefix allowed",
			extraEnv: []string{"FAKE_CODER_EXIT_AFTER_MS=1", "CODER_CLIENT_TLS_CA_FILE=/run/secrets/ca.pem"},
			wantCode: 0,
		},
		{
			name:       "SSH_AUTH_SOCK poison",
			extraEnv:   []string{"SSH_AUTH_SOCK=/tmp/agent.sock"},
			wantCode:   72,
			wantStderr: "SSH_AUTH_SOCK",
		},
		{
			name:       "LD_PRELOAD poison",
			extraEnv:   []string{"LD_PRELOAD=/tmp/evil.so"},
			wantCode:   72,
			wantStderr: "LD_PRELOAD",
		},
		{
			name:       "unparseable delay knob",
			extraEnv:   []string{"FAKE_CODER_DELAY=bogus"},
			wantCode:   70,
			wantStderr: "FAKE_CODER_DELAY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := baseArgv()
			if tt.mutateArgs != nil {
				args = tt.mutateArgs(args)
			}
			env := testutil.FakeEnv(testToken)
			if tt.dropEnv != "" {
				env = slices.DeleteFunc(slices.Clone(env), func(kv string) bool {
					return strings.HasPrefix(kv, tt.dropEnv)
				})
			}
			env = append(env, tt.extraEnv...)

			code, stdout, stderr := runFake(t, env, args)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, tt.wantCode, stderr)
			}
			if tt.wantStderr != "" && !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr = %q, want substring %q", stderr, tt.wantStderr)
			}
			// §18.5: stdout is the protocol channel. A contract failure must
			// never write a single diagnostic byte to it.
			if stdout != "" {
				t.Errorf("stdout = %q, want empty (§18.5 violation)", stdout)
			}
			if strings.Contains(stderr, testToken) {
				t.Errorf("stderr leaks the token value")
			}
		})
	}
}

func TestFakeCoderStderrKnob(t *testing.T) {
	defer testleaks.Verify(t)

	code, stdout, stderr := runFake(t,
		append(testutil.FakeEnv(testToken),
			"FAKE_CODER_STDERR=controlled diagnostic line",
			"FAKE_CODER_EXIT_AFTER_MS=1"),
		baseArgv())
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "controlled diagnostic line") {
		t.Fatalf("stderr = %q, want controlled line", stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
}

// TestFakeCoderDelayMeasured proves FAKE_CODER_DELAY postpones the first
// stdout byte — the property first-byte-timeout tests rely on.
func TestFakeCoderDelayMeasured(t *testing.T) {
	defer testleaks.Verify(t)

	const delay = 300 * time.Millisecond
	cmd := testutil.NewFakeCmd(t, testutil.BuildFakeCoder(t),
		append(testutil.FakeEnv(testToken), "FAKE_CODER_DELAY="+delay.String()),
		baseArgv()...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	start := time.Now()
	var one [1]byte
	if _, err := io.ReadFull(stdout, one[:]); err != nil {
		t.Fatalf("read first byte: %v (stderr: %s)", err, stderr.String())
	}
	elapsed := time.Since(start)
	if elapsed < delay {
		t.Fatalf("first stdout byte after %v, want >= %v", elapsed, delay)
	}
	if one[0] != 'S' {
		t.Fatalf("first byte = %q, want SSH banner start 'S'", one[0])
	}

	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	testutil.WaitReaped(cmd)
}

// TestFakeCoderSpawnChild proves the grandchild exists while the parent
// runs and that killing the parent's process group reaps it (§38.1
// descendant cleanup).
func TestFakeCoderSpawnChild(t *testing.T) {
	defer testleaks.Verify(t)

	cmd := testutil.NewFakeCmd(t, testutil.BuildFakeCoder(t),
		append(testutil.FakeEnv(testToken), "FAKE_CODER_SPAWN_CHILD=1"),
		baseArgv()...)
	// Hold stdin open: with the default nil stdin the fake reads EOF from
	// /dev/null, the handshake fails, and the parent exits before the
	// grandchild can be observed.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	defer stdin.Close()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	defer stdout.Close()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	parent := cmd.Process.Pid
	var grandchild int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if kids := childPidsOf(parent); len(kids) > 0 {
			grandchild = kids[0]
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if grandchild == 0 {
		t.Fatalf("no grandchild of pid %d appeared (stderr: %s)", parent, stderr.String())
	}

	_ = syscall.Kill(-parent, syscall.SIGKILL)
	testutil.WaitReaped(cmd)

	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(grandchild, 0); err != nil {
			return // grandchild reaped: process-group kill worked
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("grandchild pid %d survived process-group kill", grandchild)
}

// childPidsOf scans /proc for direct children of pid (Linux-only, matching
// the gateway's deployment target).
func childPidsOf(pid int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var kids []int
	for _, e := range entries {
		cp, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		stat, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		// comm may contain spaces/parens; ppid is the field after the last ')'.
		rest := stat[bytes.LastIndexByte(stat, ')')+2:]
		fields := bytes.Fields(rest)
		if len(fields) < 2 {
			continue
		}
		ppid, err := strconv.Atoi(string(fields[1]))
		if err == nil && ppid == pid {
			kids = append(kids, cp)
		}
	}
	return kids
}

func TestFakeCoderIgnoreSigterm(t *testing.T) {
	defer testleaks.Verify(t)

	cmd := testutil.NewFakeCmd(t, testutil.BuildFakeCoder(t),
		append(testutil.FakeEnv(testToken),
			"FAKE_CODER_IGNORE_SIGTERM=1",
			"FAKE_CODER_NO_STDOUT=1"),
		baseArgv()...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("process died from SIGTERM, want it ignored: %v", err)
	}

	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	testutil.WaitReaped(cmd)
}

func TestFakeCoderRecord(t *testing.T) {
	defer testleaks.Verify(t)

	recordPath := filepath.Join(t.TempDir(), "record.jsonl")
	args := baseArgv()
	code, _, stderr := runFake(t,
		append(testutil.FakeEnv(testToken),
			"FAKE_CODER_RECORD="+recordPath,
			"FAKE_CODER_EXIT_AFTER_MS=1"),
		args)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}

	records := testutil.ReadFakeRecords(t, recordPath)
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	r := records[0]
	if !slices.Equal(r.Argv, args) {
		t.Errorf("recorded argv = %v, want %v", r.Argv, args)
	}
	if !slices.Contains(r.EnvKeys, "CODER_SESSION_TOKEN") {
		t.Errorf("recorded env keys missing CODER_SESSION_TOKEN: %v", r.EnvKeys)
	}
	if !slices.IsSorted(r.EnvKeys) {
		t.Errorf("recorded env keys not sorted: %v", r.EnvKeys)
	}
	if r.TokenLength != len(testToken) {
		t.Errorf("token_length = %d, want %d", r.TokenLength, len(testToken))
	}

	raw, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	if strings.Contains(string(raw), testToken) {
		t.Errorf("record file leaks the token value")
	}
}

// TestFakeInnerSSH is the full round trip: spawn the fake with the valid
// §18 contract, run a real x/crypto SSH client over its stdio pipes, and
// exec through the in-memory inner server (§38.2).
func TestFakeInnerSSH(t *testing.T) {
	defer testleaks.Verify(t)

	cmd := testutil.NewFakeCmd(t, testutil.BuildFakeCoder(t),
		testutil.FakeEnv(testToken), baseArgv()...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	conn, chans, reqs, err := ssh.NewClientConn(
		innerssh.NewConn(stdout, stdin),
		"fake-coder-stdio",
		&ssh.ClientConfig{
			User:            "integration-test",
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		},
	)
	if err != nil {
		t.Fatalf("client handshake: %v (stderr: %s)", err, stderr.String())
	}
	client := ssh.NewClient(conn, chans, reqs)

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	out, err := session.Output("hello")
	if err != nil {
		t.Fatalf("exec hello: %v (stderr: %s)", err, stderr.String())
	}
	if string(out) != "ECHO:hello" {
		t.Fatalf("exec output = %q, want %q", out, "ECHO:hello")
	}
	session.Close()
	client.Close()

	// Closing the client's stdin write side delivers EOF; the fake's inner
	// server then shuts down and the process must exit 0.
	stdin.Close()
	if code := testutil.WaitReaped(cmd); code != 0 {
		t.Fatalf("fake exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
}
