//go:build fakecoder

// fake-coder is a TEST-ONLY stand-in for /usr/local/bin/coder. It is never
// shipped in the production image. Build it explicitly with:
//
//	go build -tags fakecoder ./internal/testutil/fake-coder/
//
// The binary asserts the §18.2/§18.3 spawn contract that the real gateway
// must honor, then exposes the in-memory inner SSH server
// (internal/testutil/innerssh) over its stdin/stdout per §18.5.
//
// Exit codes (stable — downstream tests T16/T18/T23 switch on these):
//
//	70  argv/env contract violation (bad argv shape, missing token in env,
//	    token present in argv)
//	71  unexpected ambient CODER_* variable beyond the §18.3 allowlist
//	72  poisoned environment (SSH_AUTH_SOCK or LD_PRELOAD present)
//	1   inner SSH server failure after the contract checks passed
//
// All diagnostics go to stderr ONLY. Stdout is the SSH protocol channel
// (§18.5); one stray byte there corrupts the handshake. Token VALUES are
// never printed anywhere — diagnostics and RECORD entries carry the token
// LENGTH only.
//
// Behavior knobs (environment, all FAKE_CODER_*):
//
//	FAKE_CODER_DELAY=<duration>     sleep before the first stdout byte
//	                                (e.g. "300ms"); first-byte timing tests
//	FAKE_CODER_STDERR=<text>        write <text> to stderr, then continue
//	FAKE_CODER_EXIT_AFTER_MS=<ms>   sleep <ms> after DELAY, then exit with
//	FAKE_CODER_EXIT_CODE=<code>     this code (default 0); early-exit tests
//	FAKE_CODER_NO_STDOUT=1          never write stdout; block until killed
//	                                (first-byte timeout tests)
//	FAKE_CODER_SPAWN_CHILD=1        fork a sleeping grandchild (re-exec of
//	                                this binary) for process-group kill tests
//	FAKE_CODER_IGNORE_SIGTERM=1     trap and ignore SIGTERM; only SIGKILL
//	                                stops us (KILL escalation tests)
//	FAKE_CODER_RECORD=<file>        append one JSON line: full argv, sorted
//	                                env KEY names, token LENGTH — never values
//
// Knob parse failures exit 70 (harness misuse is a contract violation).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/taxilian/coder-ssh-gateway/internal/testutil/innerssh"
)

const (
	exitContract = 70 // argv/token contract violation
	exitAmbient  = 71 // unexpected ambient CODER_* variable
	exitPoison   = 72 // SSH_AUTH_SOCK / LD_PRELOAD present
)

// coderEnvAllowlist mirrors the §18.3 environment the gateway may pass.
var coderEnvAllowlist = map[string]bool{
	"CODER_URL":                       true,
	"CODER_SESSION_TOKEN":             true,
	"CODER_NO_VERSION_WARNING":        true,
	"CODER_NO_FEATURE_WARNING":        true,
	"CODER_DISABLE_NETWORK_TELEMETRY": true,
}

func main() {
	if os.Getenv("FAKE_CODER_GRANDCHILD") == "1" {
		grandchildMain()
		return
	}

	recordEnv()

	validateArgv()
	validateEnv()
	applyKnobs()

	if os.Getenv("FAKE_CODER_SPAWN_CHILD") == "1" {
		spawnGrandchild()
	}
	if os.Getenv("FAKE_CODER_IGNORE_SIGTERM") == "1" {
		ignoreSigterm()
	}

	if os.Getenv("FAKE_CODER_NO_STDOUT") == "1" {
		blockForever()
		return
	}

	if err := innerssh.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "fake-coder: inner ssh: %v\n", err)
		os.Exit(1)
	}
}

// validateArgv enforces the exact §18.2 process form:
//
//	--global-config <dir> ssh --stdio --hostname-suffix <suffix>
//	--wait=<yes|no|auto> [--disable-autostart=true] <target>
//
// It also requires CODER_SESSION_TOKEN in the environment and rejects any
// argv element containing the token value (§18.3).
func validateArgv() {
	args := os.Args[1:]

	fail := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "fake-coder: argv contract: "+format+"\n", a...)
		os.Exit(exitContract)
	}

	if len(args) != 8 && len(args) != 9 {
		fail("want 8 or 9 arguments, got %d", len(args))
	}
	if args[0] != "--global-config" {
		fail("arg[0]: want --global-config, got %q", args[0])
	}
	if args[1] == "" || strings.HasPrefix(args[1], "-") {
		fail("arg[1]: --global-config value missing or looks like a flag: %q", args[1])
	}
	if args[2] != "ssh" {
		fail("arg[2]: want subcommand ssh, got %q", args[2])
	}
	if args[3] != "--stdio" {
		fail("arg[3]: want --stdio, got %q", args[3])
	}
	if args[4] != "--hostname-suffix" {
		fail("arg[4]: want --hostname-suffix, got %q", args[4])
	}
	if args[5] == "" || strings.HasPrefix(args[5], "-") {
		fail("arg[5]: --hostname-suffix value missing or looks like a flag: %q", args[5])
	}
	mode, ok := strings.CutPrefix(args[6], "--wait=")
	if !ok {
		fail("arg[6]: want --wait=<mode>, got %q", args[6])
	}
	switch mode {
	case "yes", "no", "auto":
	default:
		fail("arg[6]: invalid --wait mode %q", mode)
	}

	target := args[7]
	if len(args) == 9 {
		if args[7] != "--disable-autostart=true" {
			fail("arg[7]: want --disable-autostart=true, got %q", args[7])
		}
		target = args[8]
	}
	if target == "" || strings.HasPrefix(target, "-") {
		fail("target positional missing or looks like a flag: %q", target)
	}

	token := os.Getenv("CODER_SESSION_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "fake-coder: CODER_SESSION_TOKEN missing from environment")
		os.Exit(exitContract)
	}
	// §18.3: the token must never appear in argv. Containment (not
	// equality) catches `target=<token>` and flag-smuggling alike.
	for i, a := range args {
		if strings.Contains(a, token) {
			fmt.Fprintf(os.Stderr, "fake-coder: token leaked into argv[%d] (token length %d)\n", i, len(token))
			os.Exit(exitContract)
		}
	}
}

// validateEnv enforces the §18.3 environment rules: no unexpected ambient
// CODER_* variables (exit 71), and no poisoned loader/agent variables
// SSH_AUTH_SOCK or LD_PRELOAD (exit 72). FAKE_CODER_* knobs are ours and
// exempt.
func validateEnv() {
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		switch key {
		case "SSH_AUTH_SOCK", "LD_PRELOAD":
			fmt.Fprintf(os.Stderr, "fake-coder: poisoned environment: %s present\n", key)
			os.Exit(exitPoison)
		}
		if !strings.HasPrefix(key, "CODER_") {
			continue
		}
		if coderEnvAllowlist[key] || strings.HasPrefix(key, "CODER_CLIENT_TLS_") {
			continue
		}
		fmt.Fprintf(os.Stderr, "fake-coder: unexpected ambient variable: %s\n", key)
		os.Exit(exitAmbient)
	}
}

// applyKnobs handles FAKE_CODER_STDERR, FAKE_CODER_DELAY, and the
// FAKE_CODER_EXIT_AFTER_MS/FAKE_CODER_EXIT_CODE early-exit pair.
func applyKnobs() {
	if s := os.Getenv("FAKE_CODER_STDERR"); s != "" {
		fmt.Fprintln(os.Stderr, s)
	}
	if d := os.Getenv("FAKE_CODER_DELAY"); d != "" {
		dur, err := time.ParseDuration(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fake-coder: bad FAKE_CODER_DELAY %q: %v\n", d, err)
			os.Exit(exitContract)
		}
		time.Sleep(dur)
	}
	if ms := os.Getenv("FAKE_CODER_EXIT_AFTER_MS"); ms != "" {
		n, err := strconv.Atoi(ms)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fake-coder: bad FAKE_CODER_EXIT_AFTER_MS %q: %v\n", ms, err)
			os.Exit(exitContract)
		}
		code := 0
		if c := os.Getenv("FAKE_CODER_EXIT_CODE"); c != "" {
			code, err = strconv.Atoi(c)
			if err != nil {
				fmt.Fprintf(os.Stderr, "fake-coder: bad FAKE_CODER_EXIT_CODE %q: %v\n", c, err)
				os.Exit(exitContract)
			}
		}
		time.Sleep(time.Duration(n) * time.Millisecond)
		os.Exit(code)
	}
}

// recordEnv appends one JSON line to FAKE_CODER_RECORD containing the full
// argv, the sorted names (never values) of every environment variable, and
// the token length. It runs BEFORE contract validation so failing spawns
// are still observable to tests.
func recordEnv() {
	path := os.Getenv("FAKE_CODER_RECORD")
	if path == "" {
		return
	}
	keys := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		keys = append(keys, key)
	}
	sort.Strings(keys)
	entry := struct {
		Argv        []string `json:"argv"`
		EnvKeys     []string `json:"env_keys"`
		TokenLength int      `json:"token_length"`
	}{
		Argv:        os.Args[1:],
		EnvKeys:     keys,
		TokenLength: len(os.Getenv("CODER_SESSION_TOKEN")),
	}
	line, err := json.Marshal(entry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fake-coder: record marshal: %v\n", err)
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fake-coder: record open %s: %v\n", path, err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s\n", line)
}

// spawnGrandchild re-executes this binary in grandchild mode. The
// grandchild shares our process group (no Setpgid), so a supervisor's
// process-group kill must reap it — exactly what §38.1 descendant-cleanup
// tests assert.
func spawnGrandchild() {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "FAKE_CODER_GRANDCHILD=1")
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "fake-coder: spawn grandchild: %v\n", err)
		os.Exit(1)
	}
}

// grandchildMain blocks until killed. It must never touch stdout.
func grandchildMain() {
	blockForever()
}

// ignoreSigterm traps SIGTERM and discards it, so only SIGKILL terminates
// the process (§38.1 TERM-ignored-then-KILL escalation tests).
func ignoreSigterm() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM)
	go func() {
		for range c {
		}
	}()
}

// blockForever sleeps until the process is killed externally.
func blockForever() {
	select {}
}
