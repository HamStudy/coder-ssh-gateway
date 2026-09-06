package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
)

type StartError struct {
	Code string
	Err  error
}

func (e *StartError) Error() string {
	return e.Code + ": " + e.Err.Error()
}

func (e *StartError) Unwrap() error {
	return e.Err
}

type Launcher struct {
	Dep core.Deployment
	Log *slog.Logger
}

type Process struct {
	Cmd       *exec.Cmd
	PID       int
	Stdin     io.WriteCloser
	Stdout    io.ReadCloser
	Stderr    io.ReadCloser
	StartedAt time.Time
	waitCh    chan error

	// drains tracks pipe consumers (stdout + stderr). os/exec closes the
	// StdoutPipe/StderrPipe read ends inside Wait, discarding any unread
	// bytes the child wrote before exiting — so Wait must not run until
	// every consumer has finished reading. Consumers signal via
	// StdoutDrained/StderrDrained; the Wait producer blocks on drains
	// before calling Cmd.Wait.
	drains          sync.WaitGroup
	stdoutDrainOnce sync.Once
	stderrDrainOnce sync.Once
}

func (p *Process) Wait() <-chan error {
	return p.waitCh
}

// StdoutDrained signals that the consumer of Stdout has finished reading.
// Idempotent. See the drains field for why Wait defers to this.
func (p *Process) StdoutDrained() {
	p.stdoutDrainOnce.Do(p.drains.Done)
}

// StderrDrained signals that the consumer of Stderr has finished reading.
// Idempotent. See the drains field for why Wait defers to this.
func (p *Process) StderrDrained() {
	p.stderrDrainOnce.Do(p.drains.Done)
}

func (l *Launcher) Launch(ctx context.Context, route core.Route, cred core.CredentialSnapshot) (*Process, error) {
	argv := BuildArgv(l.Dep, route)
	if argv == nil {
		return nil, fmt.Errorf("TUNNEL_PROCESS_START_FAILED: %w", &StartError{Code: core.TUNNEL_PROCESS_START_FAILED, Err: fmt.Errorf("invalid workspace host")})
	}

	env := BuildEnv(l.Dep, cred.Token)
	for i := range cred.Token {
		cred.Token[i] = 0
	}

	cmd := exec.Command(l.Dep.CoderBinary, argv...)
	cmd.Env = env
	cmd.Dir = l.Dep.WorkingDir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("TUNNEL_PROCESS_START_FAILED: %w", &StartError{Code: core.TUNNEL_PROCESS_START_FAILED, Err: err})
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("TUNNEL_PROCESS_START_FAILED: %w", &StartError{Code: core.TUNNEL_PROCESS_START_FAILED, Err: err})
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("TUNNEL_PROCESS_START_FAILED: %w", &StartError{Code: core.TUNNEL_PROCESS_START_FAILED, Err: err})
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("TUNNEL_PROCESS_START_FAILED: %w", &StartError{Code: core.TUNNEL_PROCESS_START_FAILED, Err: err})
	}

	proc := &Process{
		Cmd:       cmd,
		PID:       cmd.Process.Pid,
		Stdin:     stdin,
		Stdout:    stdout,
		Stderr:    stderr,
		StartedAt: time.Now(),
		waitCh:    make(chan error, 1),
	}

	// Wait defers to the pipe consumers: cmd.Wait closes StdoutPipe and
	// StderrPipe after the child exits, discarding unread bytes, so it must
	// not run until both drains signal completion (os/exec contract). On the
	// cancellation path the TERM->KILL ladder kills the child first; the
	// pipes then reach EOF and the drains complete, unblocking Wait.
	proc.drains.Add(2)
	go func() {
		proc.drains.Wait()
		proc.waitCh <- cmd.Wait()
	}()

	return proc, nil
}

func LogVersions(ctx context.Context, log *slog.Logger, dep core.Deployment) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, dep.CoderBinary, "version")
	cmd.Dir = dep.WorkingDir

	out, err := cmd.Output()
	if err != nil {
		log.Log(ctx, slog.LevelWarn, "version command failed", "error", err)
		return
	}
	log.Log(ctx, slog.LevelInfo, "coder version", "output", string(out))
}
