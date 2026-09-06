// Package app implements the coder-ssh-gateway command-line surface (§29):
// serve, init, admin, and doctor, plus the glue that assembles the full
// system from config, store, secretbox, coderapi, sshauth, server, tunnel,
// and maintenance (§24).
//
// Conventions:
//   - Tokens NEVER appear as command-line arguments (§29); credential set
//     reads from stdin or a hidden TTY prompt.
//   - Diagnostics go to stderr; command output goes to stdout.
//   - Every command that touches state opens the store fresh and closes it
//     before returning; nothing holds the flock after the command exits.
package app

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/HamStudy/coder-ssh-gateway/internal/version"
)

// Exit codes (§29 operator-facing commands; Unix conventions).
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// cli carries the shared command context: global flags and I/O streams.
type cli struct {
	ctx            context.Context
	stateDir       string // --state-dir (wins over config state.dir, §T2 ApplyStateDir)
	configPath     string // --config
	listenAddress  explicitString
	metricsAddress explicitString
	healthAddress  explicitString
	stdin          io.Reader
	stdinBuf       *bufio.Reader // lazily shared so token + confirmation lines both survive
	stdout         io.Writer
	stderr         io.Writer
}

// explicitString distinguishes an omitted global flag from a supplied value.
type explicitString struct {
	value string
	set   bool
}

// Run executes args (excluding argv[0]) and returns the process exit code.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	c := &cli{ctx: ctx, stdin: stdin, stdout: stdout, stderr: stderr}
	rest, err := c.parseGlobalFlags(args)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		usage(stderr)
		return exitUsage
	}
	if len(rest) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch rest[0] {
	case "serve":
		return c.cmdServe(rest[1:])
	case "init":
		return c.cmdInit(rest[1:])
	case "admin":
		return c.cmdAdmin(rest[1:])
	case "doctor":
		return c.cmdDoctor(rest[1:])
	case "version":
		fmt.Fprintln(c.stdout, version.String())
		return exitOK
	case "help", "-h", "--help":
		usage(c.stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "error: unknown command %q\n", rest[0])
		usage(stderr)
		return exitUsage
	}
}

// parseGlobalFlags peels persistent flags off the front of args and returns
// the remaining command line. Global flags must precede the subcommand.
func (c *cli) parseGlobalFlags(args []string) ([]string, error) {
	for len(args) > 0 {
		a := args[0]
		var name, val string
		switch {
		case a == "--":
			return args[1:], nil
		case isGlobalValueFlag(a):
			name = a
			if len(args) < 2 {
				return nil, fmt.Errorf("flag %s requires a value", name)
			}
			val = args[1]
			args = args[2:]
		case globalFlagWithValue(a) != "":
			name, val, _ = strings.Cut(a, "=")
			args = args[1:]
		default:
			return args, nil
		}
		if val == "" {
			return nil, fmt.Errorf("flag %s requires a non-empty value", name)
		}
		switch name {
		case "--state-dir":
			stateDir, err := filepath.Abs(val)
			if err != nil {
				return nil, fmt.Errorf("resolve --state-dir %q: %w", val, err)
			}
			c.stateDir = stateDir
		case "--config":
			c.configPath = val
		case "--listen-address":
			c.listenAddress = explicitString{value: val, set: true}
		case "--metrics-address":
			c.metricsAddress = explicitString{value: val, set: true}
		case "--health-address":
			c.healthAddress = explicitString{value: val, set: true}
		}
	}
	return args, nil
}

func isGlobalValueFlag(arg string) bool {
	switch arg {
	case "--state-dir", "--config", "--listen-address", "--metrics-address", "--health-address":
		return true
	default:
		return false
	}
}

func globalFlagWithValue(arg string) string {
	name, _, ok := strings.Cut(arg, "=")
	if ok && isGlobalValueFlag(name) {
		return name
	}
	return ""
}

func usage(w io.Writer) {
	fmt.Fprint(w, `coder-ssh-gateway — SSH jump gateway bridging to Coder workspaces

Usage:
  coder-ssh-gateway [global flags] <command> [flags]

Commands:
  serve      Run the gateway (config -> store -> SSH server) until signaled
	init       Initialize a state directory for a Coder domain (for example: init coder.example.com)
  admin      Offline administration: account, key, credential, disconnect
  doctor     Diagnose configuration, state, secrets, and Coder reachability
  version    Print version information

Global flags:
  --state-dir DIR          State directory; wins over state.dir in the config file
  --config FILE            Config file (default: <state-dir>/config.yaml)
  --listen-address ADDR    SSH bind address; serve only, wins over CSGW_LISTEN_ADDRESS
  --metrics-address ADDR   Metrics bind address; serve only, wins over CSGW_METRICS_ADDRESS
  --health-address ADDR    Health bind address; serve only, wins over CSGW_HEALTH_ADDRESS

Run 'coder-ssh-gateway <command> --help' for command-specific flags.
`)
}

// newFlagSet builds a subcommand flag set writing parse errors to stderr.
func (c *cli) newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	return fs
}

// stdinReader returns the one shared buffered stdin reader so that a token
// line and a following confirmation line are both preserved.
func (c *cli) stdinReader() *bufio.Reader {
	if c.stdinBuf == nil {
		c.stdinBuf = bufio.NewReader(c.stdin)
	}
	return c.stdinBuf
}

// readLine reads one line from the shared stdin reader (EOF-tolerant).
func (c *cli) readLine() (string, error) {
	line, err := c.stdinReader().ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return trimLineEnd(line), nil
}

func trimLineEnd(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
