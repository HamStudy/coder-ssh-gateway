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

	"golang.org/x/crypto/ssh"
)

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
type subsystemRequest struct{ Name string }

// sessionPipes carries the bridge-managed inner stream completion signals.
type sessionPipes struct {
	stdoutDone <-chan struct{}
	stderrDone <-chan struct{}
}

func forwardSessionRequests(ctx context.Context, channel ssh.Channel, session *ssh.Session, requests <-chan *ssh.Request, pipes *sessionPipes, queued []QueuedSessionRequest) error {
	started := false
	var waitCh <-chan error
	// Requests accepted while the transport was still starting (§19.9
	// optimistic acks) replay here, in arrival order, before live traffic.
	for _, q := range queued {
		ok, done, wait, reason := applySessionRequest(session, q.Type, q.Payload, &started, pipes)
		if !ok || done {
			slog.Warn("queued session request failed on replay",
				slog.String("request_type", q.Type),
				slog.String("reason", reason),
			)
			return fmt.Errorf("queued %s request failed on inner session", q.Type)
		}
		if wait != nil && waitCh == nil {
			result := make(chan error, 1)
			go func() { result <- wait() }()
			waitCh = result
		}
	}
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
				slog.Debug("nil request on session channel; ignored")
				continue
			}
			ok, done, wait, reason := applySessionRequest(session, req.Type, req.Payload, &started, pipes)
			if !ok {
				// A false reply here is client-visible and may be fatal to
				// the client's session (§19.9 lesson): rejections are never
				// silent, and validation failures warn at operator level.
				slog.Warn("session request rejected",
					slog.String("request_type", req.Type),
					slog.String("reason", reason),
					slog.Bool("started", started),
				)
			}
			if req.WantReply {
				_ = req.Reply(ok, nil)
			}
			if done {
				return errors.New("workspace session start failed")
			}
			if wait != nil && waitCh == nil {
				result := make(chan error, 1)
				go func() { result <- wait() }()
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

// applySessionRequest validates and applies one outer session request to
// the inner session. ok=false means the request is refused (client-visible
// false reply; reason says why — rejections are never silent); done=true
// means the session start failed terminally.
func applySessionRequest(session *ssh.Session, typ string, payload []byte, started *bool, pipes *sessionPipes) (ok, done bool, wait func() error, reason string) {
	if *started {
		switch typ {
		case "window-change":
			var r windowChangeRequest
			if ssh.Unmarshal(payload, &r) != nil || !validDimensions(r.Columns, r.Rows, r.Width, r.Height) {
				return false, false, nil, "malformed window-change"
			}
			return session.WindowChange(int(r.Rows), int(r.Columns)) == nil, false, nil, ""
		case "signal":
			var r signalRequest
			if ssh.Unmarshal(payload, &r) != nil || !validSignal(r.Signal) {
				return false, false, nil, "malformed or unsupported signal"
			}
			return session.Signal(ssh.Signal(r.Signal)) == nil, false, nil, ""
		default:
			return false, false, nil, "request not applicable after session start"
		}
	}

	switch typ {
	case "env":
		var r envRequest
		if ssh.Unmarshal(payload, &r) != nil || !validSessionString(r.Name, 256) || !validSessionString(r.Value, 32*1024) {
			return false, false, nil, "malformed or invalid env request"
		}
		if session.Setenv(r.Name, r.Value) != nil {
			return false, false, nil, "inner refused env"
		}
		return true, false, nil, ""
	case "auth-agent-req@openssh.com":
		// ssh -A: mirror the request; the workspace then opens auth-agent
		// channels, relayed to the client's agent by the transport.
		innerOK, err := session.SendRequest("auth-agent-req@openssh.com", true, payload)
		if err != nil || !innerOK {
			return false, false, nil, "inner refused agent forwarding"
		}
		return innerOK, false, nil, ""
	case "subsystem":
		// SFTP/scp: a start request like exec; the inner server owns the
		// subsystem name allowlist. RequestSubsystem skips x/crypto's pipe
		// setup, so the wait function tracks the manual copies instead of
		// session.Wait.
		var r subsystemRequest
		if ssh.Unmarshal(payload, &r) != nil || !validSessionString(r.Name, 64) {
			return false, false, nil, "malformed or invalid subsystem request"
		}
		innerOK, err := session.SendRequest("subsystem", true, ssh.Marshal(struct{ Subsystem string }{r.Name}))
		if err != nil || !innerOK {
			return false, true, nil, "inner refused subsystem"
		}
		*started = true
		return true, false, func() error {
			<-pipes.stdoutDone
			<-pipes.stderrDone
			_ = session.Close()
			return nil
		}, ""
	case "pty-req":
		r, modes, err := parsePtyRequest(payload)
		if err != nil {
			return false, false, nil, "invalid pty-req: " + err.Error()
		}
		if err := session.RequestPty(r.Term, int(r.Rows), int(r.Columns), modes); err != nil {
			return false, false, nil, "inner refused pty: " + err.Error()
		}
		return true, false, nil, ""
	case "window-change":
		var r windowChangeRequest
		if ssh.Unmarshal(payload, &r) != nil || !validDimensions(r.Columns, r.Rows, r.Width, r.Height) {
			return false, false, nil, "malformed window-change"
		}
		return session.WindowChange(int(r.Rows), int(r.Columns)) == nil, false, nil, ""
	case "shell":
		if len(payload) != 0 {
			return false, false, nil, "shell request carries unexpected payload"
		}
		if err := session.Shell(); err != nil {
			return false, true, nil, "inner refused shell"
		}
		*started = true
		return true, false, waitDrained(session, pipes), ""
	case "exec":
		var r execRequest
		if ssh.Unmarshal(payload, &r) != nil || !validSessionString(r.Command, 4096) {
			return false, false, nil, "malformed or invalid exec request"
		}
		if err := session.Start(r.Command); err != nil {
			return false, true, nil, "inner refused exec"
		}
		*started = true
		return true, false, waitDrained(session, pipes), ""
	default:
		return false, false, nil, "unsupported request type"
	}
}

// waitDrained keeps the old guarantee that output reaches the outer channel
// before the wait result surfaces: exit status first, then copy completion.
func waitDrained(session *ssh.Session, pipes *sessionPipes) func() error {
	return func() error {
		err := session.Wait()
		<-pipes.stdoutDone
		<-pipes.stderrDone
		return err
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

// parsePtyRequest validates an RFC 4254 pty-req payload for relay to the
// inner session. Term may be empty (mobile clients omit it); an empty modes
// string means "no modes". Shared by the live bridge and the deferred
// bridge's queueDecision so both accept identically.
func parsePtyRequest(payload []byte) (ptyRequest, ssh.TerminalModes, error) {
	var r ptyRequest
	if ssh.Unmarshal(payload, &r) != nil {
		return r, nil, errors.New("malformed pty-req payload")
	}
	if len(r.Term) > 256 || strings.ContainsRune(r.Term, 0) {
		return r, nil, errors.New("invalid terminal name")
	}
	if !validDimensions(r.Columns, r.Rows, r.Width, r.Height) {
		return r, nil, errors.New("invalid pty dimensions")
	}
	modes, err := parseTerminalModes([]byte(r.Modes))
	if err != nil {
		if len(r.Modes) == 0 {
			modes = ssh.TerminalModes{}
		} else {
			return r, nil, err
		}
	}
	return r, modes, nil
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
