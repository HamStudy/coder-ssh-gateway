package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"syscall"
	"time"

	"github.com/taxilian/coder-ssh-gateway/internal/core"
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
}

func (p *Process) Wait() <-chan error {
	return p.waitCh
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

	go func() {
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
