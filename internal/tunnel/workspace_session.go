package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
)

// WorkspaceSessionStarter terminates the SSH protocol exposed by `coder ssh
// --stdio` and forwards an outer session channel to a fresh inner session.
// It intentionally does not use the byte-copy tunnel proxy: the child stdio
// is an SSH transport, not terminal bytes.
type WorkspaceSessionStarter struct {
	Launcher        *Launcher
	StartupTimeout  time.Duration
	ShutdownGrace   time.Duration
	StderrRingBytes int64
	Log             *slog.Logger
	Rechecker       *Rechecker
	Registry        *Registry
	// NewStartupTimer is injectable for deterministic lifecycle tests. Nil uses
	// a real timer and is stopped immediately after inner SSH startup succeeds.
	NewStartupTimer func(time.Duration) (<-chan time.Time, func())
}

var _ interface {
	Start(context.Context, ssh.Channel, <-chan *ssh.Request, string, core.CredentialSnapshot) error
} = (*WorkspaceSessionStarter)(nil)

func (s *WorkspaceSessionStarter) Start(ctx context.Context, channel ssh.Channel, requests <-chan *ssh.Request, target string, credential core.CredentialSnapshot) error {
	log := s.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if s.Launcher == nil {
		return s.fail(channel, "workspace is unavailable", core.TUNNEL_PROCESS_START_FAILED, fmt.Errorf("nil launcher"))
	}
	route := core.Route{WorkspaceHost: target, DisplayTarget: target}
	if err := EnsureGlobalConfigDir(s.Launcher.Dep.GlobalConfig); err != nil {
		return s.fail(channel, "workspace is unavailable", core.TUNNEL_PROCESS_START_FAILED, err)
	}
	proc, err := s.Launcher.Launch(ctx, route, credential)
	if err != nil {
		return s.fail(channel, "workspace is unavailable", core.TUNNEL_PROCESS_START_FAILED, err)
	}
	var sessionID uuid.UUID
	if s.Registry != nil {
		sessionID = uuid.New()
		s.Registry.Add(TunnelInfo{
			ID:           sessionID,
			AccountID:    credential.AccountID,
			DeploymentID: s.Launcher.Dep.ID,
			Generation:   credential.Generation,
			Route:        route,
			StartedAt:    time.Now(),
			ConnectionID: credential.AccountID.String(),
		})
		defer s.Registry.Remove(sessionID)
	}

	ring := NewStderrRing(s.StderrRingBytes)
	stderrDone := make(chan struct{})
	go func() {
		defer proc.StderrDrained()
		_, _ = io.Copy(ring, proc.Stderr)
		close(stderrDone)
	}()

	innerConn := &stdioConn{r: proc.Stdout, w: proc.Stdin, closeFn: func() {
		_ = proc.Stdin.Close()
		_ = proc.Stdout.Close()
	}}
	stdoutDrained := false
	defer func() {
		if !stdoutDrained {
			proc.StdoutDrained()
		}
		_ = innerConn.Close()
	}()

	startupTimeout := s.StartupTimeout
	if startupTimeout <= 0 {
		startupTimeout = DefaultStartupTimeout
	}
	newTimer := s.NewStartupTimer
	if newTimer == nil {
		newTimer = realTimer
	}
	startupC, stopStartup := newTimer(startupTimeout)
	watchdogDone := make(chan struct{})
	watchdogStopped := make(chan struct{})
	watchdogTimedOut := make(chan struct{})
	go func() {
		defer close(watchdogStopped)
		select {
		case <-startupC:
			close(watchdogTimedOut)
			_ = innerConn.Close()
			requestProcessTermination(proc)
		case <-ctx.Done():
			_ = innerConn.Close()
			requestProcessTermination(proc)
		case <-watchdogDone:
		}
	}()

	conn, chans, reqs, err := ssh.NewClientConn(innerConn, target, &ssh.ClientConfig{
		User:            "coder",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         startupTimeout,
	})
	close(watchdogDone)
	<-watchdogStopped
	stopStartup()
	if err != nil {
		_ = innerConn.Close()
		proc.StdoutDrained()
		stdoutDrained = true
		_ = terminateProcess(proc, s.ShutdownGrace)
		<-stderrDone
		code := core.TUNNEL_CODER_EXITED
		select {
		case <-watchdogTimedOut:
			code = core.TUNNEL_START_TIMEOUT
		default:
		}
		s.recheckAfterFailure(ctx, credential, code)
		log.Debug("workspace inner SSH handshake failed", slog.String("code", code), slog.String("stderr_tail", string(ring.Tail())))
		return s.fail(channel, "workspace target is invalid or unavailable", code, err)
	}
	client := ssh.NewClient(conn, chans, reqs)

	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		_ = innerConn.Close()
		proc.StdoutDrained()
		stdoutDrained = true
		_ = terminateProcess(proc, s.ShutdownGrace)
		<-stderrDone
		return s.fail(channel, "workspace target is invalid or unavailable", core.TUNNEL_CODER_EXITED, err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		_ = client.Close()
		_ = innerConn.Close()
		proc.StdoutDrained()
		stdoutDrained = true
		_ = terminateProcess(proc, s.ShutdownGrace)
		<-stderrDone
		return s.fail(channel, "workspace session failed", core.TUNNEL_STREAM_FAILED, err)
	}
	session.Stdout = channel
	session.Stderr = channel.Stderr()
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		_, _ = io.Copy(stdin, channel)
		_ = stdin.Close()
	}()

	err = forwardSessionRequests(ctx, channel, session, requests)
	var exitErr *ssh.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		_ = s.fail(channel, "workspace session failed", core.TUNNEL_STREAM_FAILED, err)
		log.Debug("workspace session failed", slog.String("target", route.DisplayTarget), slog.String("stderr_tail", string(ring.Tail())))
	}
	// Wait owns the inner stdout/stderr copy functions, so all output has
	// reached the outer channel before it returns.
	_ = channel.Close()
	<-inputDone
	_ = session.Close()
	_ = client.Close()
	_ = innerConn.Close()
	proc.StdoutDrained()
	stdoutDrained = true
	_ = terminateProcess(proc, s.ShutdownGrace)
	<-stderrDone
	if err != nil && !errors.As(err, &exitErr) {
		return &StartError{Code: core.TUNNEL_STREAM_FAILED, Err: err}
	}
	return nil
}

func (s *WorkspaceSessionStarter) recheckAfterFailure(ctx context.Context, credential core.CredentialSnapshot, code string) {
	if s.Rechecker != nil && (code == core.TUNNEL_CODER_EXITED || code == core.TUNNEL_START_TIMEOUT) {
		s.Rechecker.RecheckAfterFailure(ctx, credential.AccountID, credential.Generation)
	}
}

func (s *WorkspaceSessionStarter) fail(channel ssh.Channel, message, code string, err error) error {
	_, _ = channel.Stderr().Write([]byte(message + "\r\n"))
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 255}))
	_ = channel.CloseWrite()
	return &StartError{Code: code, Err: err}
}

func terminateProcess(proc *Process, grace time.Duration) error {
	requestProcessTermination(proc)
	if grace <= 0 {
		grace = DefaultShutdownGrace
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-proc.Wait():
		return err
	case <-timer.C:
		_ = syscall.Kill(-proc.PID, syscall.SIGKILL)
		return <-proc.Wait()
	}
}

func requestProcessTermination(proc *Process) {
	_ = proc.Stdin.Close()
	_ = syscall.Kill(-proc.PID, syscall.SIGTERM)
}

type stdioConn struct {
	r       io.Reader
	w       io.Writer
	closeFn func()
	once    sync.Once
}

func (c *stdioConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *stdioConn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *stdioConn) Close() error {
	c.once.Do(c.closeFn)
	return nil
}
func (c *stdioConn) LocalAddr() net.Addr              { return sessionAddr("local") }
func (c *stdioConn) RemoteAddr() net.Addr             { return sessionAddr("remote") }
func (c *stdioConn) SetDeadline(time.Time) error      { return nil }
func (c *stdioConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stdioConn) SetWriteDeadline(time.Time) error { return nil }

type sessionAddr string

func (a sessionAddr) Network() string { return "stdio" }
func (a sessionAddr) String() string  { return string(a) }

type envRequest struct{ Name, Value string }
type ptyRequest struct {
	Term          string
	Columns, Rows uint32
	Width, Height uint32
	Modes         string
}
type windowChangeRequest struct{ Columns, Rows, Width, Height uint32 }
type execRequest struct{ Command string }
type signalRequest struct{ Signal string }

func forwardSessionRequests(ctx context.Context, channel ssh.Channel, session *ssh.Session, requests <-chan *ssh.Request) error {
	started := false
	var waitCh <-chan error
	for {
		select {
		case <-ctx.Done():
			return abortSession(session, waitCh, ctx.Err())
		case err := <-waitCh:
			return finishSession(channel, err)
		case req, ok := <-requests:
			if !ok {
				if !started {
					return errors.New("workspace session closed before shell or exec")
				}
				return abortSession(session, waitCh, errors.New("outer workspace session closed"))
			}
			if req == nil {
				continue
			}
			ok, done, waitable := handleSessionRequest(session, req, &started)
			if req.WantReply {
				_ = req.Reply(ok, nil)
			}
			if done {
				return errors.New("workspace session start failed")
			}
			if waitable && waitCh == nil {
				result := make(chan error, 1)
				go func() { result <- session.Wait() }()
				waitCh = result
			}
		}
	}
}

// abortSession closes an established inner channel and collects the only
// Session.Wait result before returning. This keeps the wait goroutine owned by
// forwardSessionRequests and prevents it from surviving outer cancellation.
func abortSession(session *ssh.Session, waitCh <-chan error, cause error) error {
	if waitCh == nil {
		return cause
	}
	_ = session.Close()
	<-waitCh
	return cause
}

func handleSessionRequest(session *ssh.Session, req *ssh.Request, started *bool) (ok, done, waitable bool) {
	if *started {
		switch req.Type {
		case "window-change":
			var r windowChangeRequest
			if ssh.Unmarshal(req.Payload, &r) != nil || !validDimensions(r.Columns, r.Rows, r.Width, r.Height) {
				return false, false, false
			}
			return session.WindowChange(int(r.Rows), int(r.Columns)) == nil, false, false
		case "signal":
			var r signalRequest
			if ssh.Unmarshal(req.Payload, &r) != nil || !validSignal(r.Signal) {
				return false, false, false
			}
			return session.Signal(ssh.Signal(r.Signal)) == nil, false, false
		default:
			return false, false, false
		}
	}

	switch req.Type {
	case "env":
		var r envRequest
		if ssh.Unmarshal(req.Payload, &r) != nil || !validSessionString(r.Name, 256) || !validSessionString(r.Value, 32*1024) {
			return false, false, false
		}
		return session.Setenv(r.Name, r.Value) == nil, false, false
	case "pty-req":
		var r ptyRequest
		if ssh.Unmarshal(req.Payload, &r) != nil || !validSessionString(r.Term, 256) || !validDimensions(r.Columns, r.Rows, r.Width, r.Height) {
			slog.Info("pty rejected at parse/validation", "payload_len", len(req.Payload), "term_len", len(r.Term))
			return false, false, false
		}
		modes, err := parseTerminalModes([]byte(r.Modes))
		if err != nil {
			slog.Info("pty rejected at modes parse", "modes_err", err.Error())
			return false, false, false
		}
		if err := session.RequestPty(r.Term, int(r.Rows), int(r.Columns), modes); err != nil {
			slog.Info("pty rejected by inner", "inner_err", err.Error())
			return false, false, false
		}
		return true, false, false
	case "window-change":
		var r windowChangeRequest
		if ssh.Unmarshal(req.Payload, &r) != nil || !validDimensions(r.Columns, r.Rows, r.Width, r.Height) {
			return false, false, false
		}
		return session.WindowChange(int(r.Rows), int(r.Columns)) == nil, false, false
	case "shell":
		if len(req.Payload) != 0 {
			return false, false, false
		}
		if err := session.Shell(); err != nil {
			return false, true, false
		}
		*started = true
		return true, false, true
	case "exec":
		var r execRequest
		if ssh.Unmarshal(req.Payload, &r) != nil || !validSessionString(r.Command, 4096) {
			return false, false, false
		}
		if err := session.Start(r.Command); err != nil {
			return false, true, false
		}
		*started = true
		return true, false, true
	default:
		return false, false, false
	}
}

func validSessionString(value string, max int) bool {
	return value != "" && len(value) <= max && !strings.ContainsRune(value, 0)
}

func validSignal(signal string) bool {
	switch ssh.Signal(signal) {
	case ssh.SIGABRT, ssh.SIGALRM, ssh.SIGFPE, ssh.SIGHUP, ssh.SIGILL,
		ssh.SIGINT, ssh.SIGKILL, ssh.SIGPIPE, ssh.SIGQUIT, ssh.SIGSEGV,
		ssh.SIGTERM, ssh.SIGUSR1, ssh.SIGUSR2:
		return true
	default:
		return false
	}
}

func validDimensions(values ...uint32) bool {
	const maxInt = uint32(1<<31 - 1)
	for _, value := range values {
		if uint64(value) > uint64(maxInt) {
			return false
		}
	}
	return true
}

func finishSession(channel ssh.Channel, err error) error {
	status := uint32(0)
	if err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			status = uint32(exitErr.ExitStatus())
		} else {
			status = 255
		}
	}
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: status}))
	_ = channel.CloseWrite()
	return err
}

func parseTerminalModes(raw []byte) (ssh.TerminalModes, error) {
	modes := make(ssh.TerminalModes)
	for len(raw) > 0 {
		op := raw[0]
		raw = raw[1:]
		if op == 0 {
			if len(raw) != 0 {
				return nil, errors.New("terminal modes contain trailing bytes")
			}
			return modes, nil
		}
		if len(raw) < 4 {
			return nil, errors.New("terminal modes truncated")
		}
		modes[op] = binary.BigEndian.Uint32(raw[:4])
		raw = raw[4:]
	}
	return nil, errors.New("terminal modes missing terminator")
}
