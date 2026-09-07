package tunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/secretbox"
)

// TransportFactory builds one SessionTransport per need: an outer connection
// lazily gets a transport for its username workspace — the session channel
// bridges through it, and direct-tcpip opens (ssh -L/-D) and tcpip-forward
// global requests (ssh -R) ride the same inner client so port forwarding
// resolves in the workspace network (§24.1 adapted).
type TransportFactory struct {
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

// QueuedSessionRequest is an outer session request that was optimistically
// accepted before the transport existed (§19.9) and replays into the inner
// session once it is ready.
type QueuedSessionRequest struct {
	Type    string
	Payload []byte
}

// WorkspaceTransport is the server-facing surface of one started transport.
// The server fakes this in unit tests; SessionTransport is the real one.
type WorkspaceTransport interface {
	// BridgeSession bridges one outer session channel to a fresh inner
	// session until the session ends, replaying any queued pre-transport
	// requests first. Blocks.
	BridgeSession(ctx context.Context, channel ssh.Channel, requests <-chan *ssh.Request, queued []QueuedSessionRequest) error
	// RelayChannel accepts one already-admitted outer direct-tcpip channel
	// and pumps it through the inner client. Blocks until the channel ends.
	// Dial failures reject the open with SSH_OPEN_CONNECT_FAILED so ssh -L
	// clients see native-style "connect failed" errors.
	RelayChannel(newCh ssh.NewChannel)
	// RelayGlobalRequest forwards a tcpip-forward/cancel-tcpip-forward
	// global request to the inner client and returns the reply.
	RelayGlobalRequest(reqType string, wantReply bool, payload []byte) (bool, []byte)
	// Close tears down the child and every relay. Idempotent.
	Close()
}

// SessionTransport is one `coder ssh --stdio` child plus its inner SSH
// client, shared by the session bridge, direct-tcpip relays, and
// tcpip-forward global requests of a single outer connection.
type SessionTransport struct {
	f          TransportFactory
	target     string
	credential core.CredentialSnapshot
	log        *slog.Logger
	out        ssh.Conn

	proc      *Process
	innerConn *stdioConn
	client    *ssh.Client

	sessionID  uuid.UUID
	registryID uuid.UUID

	wg        sync.WaitGroup
	closeOnce sync.Once
}

var _ WorkspaceTransport = (*SessionTransport)(nil)

// NewTransport spawns the child, handshakes the inner SSH client, and arms
// the inner→outer channel relays (auth-agent, forwarded-tcpip). On error the
// transport is fully torn down and a StartError is returned.
func (f *TransportFactory) NewTransport(ctx context.Context, target string, credential core.CredentialSnapshot, out ssh.Conn) (WorkspaceTransport, error) {
	log := f.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	t := &SessionTransport{
		f: *f, target: target, credential: credential, log: log, out: out,
	}
	if err := t.start(ctx); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *SessionTransport) start(ctx context.Context) error {
	route := core.Route{WorkspaceHost: t.target, DisplayTarget: t.target}
	if t.f.Launcher == nil {
		return &StartError{Code: core.TUNNEL_PROCESS_START_FAILED, Err: errors.New("nil launcher")}
	}
	if err := EnsureGlobalConfigDir(t.f.Launcher.Dep.GlobalConfig); err != nil {
		return &StartError{Code: core.TUNNEL_PROCESS_START_FAILED, Err: err}
	}
	proc, err := t.f.Launcher.Launch(ctx, route, t.credential)
	if err != nil {
		return &StartError{Code: core.TUNNEL_PROCESS_START_FAILED, Err: err}
	}
	t.proc = proc
	if t.f.Registry != nil {
		t.sessionID = uuid.New()
		t.registryID = t.sessionID
		t.f.Registry.Add(TunnelInfo{
			ID:           t.sessionID,
			AccountID:    t.credential.AccountID,
			DeploymentID: t.f.Launcher.Dep.ID,
			Generation:   t.credential.Generation,
			Route:        route,
			StartedAt:    time.Now(),
			ConnectionID: t.credential.AccountID.String(),
		})
	}

	ring := NewStderrRing(t.f.StderrRingBytes)
	stderrDone := make(chan struct{})
	go func() {
		defer proc.StderrDrained()
		_, _ = io.Copy(ring, proc.Stderr)
		close(stderrDone)
	}()
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		<-stderrDone
	}()

	t.innerConn = &stdioConn{r: proc.Stdout, w: proc.Stdin, closeFn: func() {
		_ = proc.Stdin.Close()
		_ = proc.Stdout.Close()
	}}
	stdoutDrained := false
	defer func() {
		if !stdoutDrained {
			proc.StdoutDrained()
		}
		if t.client == nil {
			t.Close()
		}
	}()

	startupTimeout := t.f.StartupTimeout
	if startupTimeout <= 0 {
		startupTimeout = DefaultStartupTimeout
	}
	newTimer := t.f.NewStartupTimer
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
			_ = t.innerConn.Close()
			requestProcessTermination(proc)
		case <-ctx.Done():
			_ = t.innerConn.Close()
			requestProcessTermination(proc)
		case <-watchdogDone:
		}
	}()

	conn, chans, reqs, err := ssh.NewClientConn(t.innerConn, t.target, &ssh.ClientConfig{
		User:            "coder",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         startupTimeout,
	})
	close(watchdogDone)
	<-watchdogStopped
	stopStartup()
	if err != nil {
		code := core.TUNNEL_CODER_EXITED
		select {
		case <-watchdogTimedOut:
			code = core.TUNNEL_START_TIMEOUT
		default:
		}
		t.recheckAfterFailure(ctx, code)
		t.log.Warn("workspace inner SSH handshake failed", slog.String("code", code), slog.String("stderr_tail", string(ring.Tail())))
		inner := &StartError{Code: code, Err: err}
		proc.StdoutDrained()
		stdoutDrained = true
		t.Close()
		return inner
	}
	t.client = ssh.NewClient(conn, chans, reqs)

	// Inner→outer relays: the workspace side opens auth-agent channels
	// (agent forwarding) and forwarded-tcpip channels (ssh -R listener
	// callbacks); each is mirrored to the outer connection verbatim.
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.relayIncoming(t.client.HandleChannelOpen("auth-agent@openssh.com"))
	}()
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.relayIncoming(t.client.HandleChannelOpen("forwarded-tcpip"))
	}()
	return nil
}

// relayIncoming mirrors every channel the inner server opens to the outer
// connection. If the outer side refuses (e.g. ssh without -A declining
// auth-agent channels) the inner channel is closed immediately.
func (t *SessionTransport) relayIncoming(incoming <-chan ssh.NewChannel) {
	for newCh := range incoming {
		inner, _, err := newCh.Accept()
		if err != nil {
			continue
		}
		outer, _, err := t.out.OpenChannel(newCh.ChannelType(), newCh.ExtraData())
		if err != nil {
			t.log.Debug("inner channel open not relayable", slog.String("channel_type", newCh.ChannelType()), slog.String("detail", err.Error()))
			_ = inner.Close()
			continue
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			relayChannels(outer, inner)
		}()
	}
}

// BridgeSession bridges one outer session channel through a fresh inner
// session. It does NOT own the transport lifecycle: the transport survives
// the session so concurrent -L/-R relays keep working (they die with the
// outer connection instead).
func (t *SessionTransport) BridgeSession(ctx context.Context, channel ssh.Channel, requests <-chan *ssh.Request, queued []QueuedSessionRequest) error {
	session, err := t.client.NewSession()
	if err != nil {
		_ = t.fail(channel, "workspace target is invalid or unavailable", core.TUNNEL_CODER_EXITED, err)
		return &StartError{Code: core.TUNNEL_CODER_EXITED, Err: err}
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		_ = t.fail(channel, "workspace session failed", core.TUNNEL_STREAM_FAILED, err)
		return &StartError{Code: core.TUNNEL_STREAM_FAILED, Err: err}
	}
	// Manual piping (see workspace_session.go): subsystem requests bypass
	// x/crypto's copy setup, so the bridge owns every direction.
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		_ = t.fail(channel, "workspace session failed", core.TUNNEL_STREAM_FAILED, err)
		return &StartError{Code: core.TUNNEL_STREAM_FAILED, Err: err}
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		_ = session.Close()
		_ = t.fail(channel, "workspace session failed", core.TUNNEL_STREAM_FAILED, err)
		return &StartError{Code: core.TUNNEL_STREAM_FAILED, Err: err}
	}
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		_, _ = io.Copy(stdin, channel)
		_ = stdin.Close()
	}()
	stdoutDone := make(chan struct{})
	go func() {
		defer close(stdoutDone)
		_, _ = io.Copy(channel, stdout)
	}()
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		_, _ = io.Copy(channel.Stderr(), stderr)
	}()
	pipes := &sessionPipes{stdoutDone: stdoutDone, stderrDone: stderrDone}

	err = forwardSessionRequests(ctx, channel, session, requests, pipes, queued)
	var exitErr *ssh.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		_ = t.fail(channel, "workspace session failed", core.TUNNEL_STREAM_FAILED, err)
		t.log.Debug("workspace session failed", slog.String("target", t.target), slog.String("detail", err.Error()))
	}
	// The wait functions drain the manual copies before returning, so all
	// output has reached the outer channel by now.
	_ = channel.Close()
	<-inputDone
	_ = session.Close()
	if err != nil && !errors.As(err, &exitErr) {
		return &StartError{Code: core.TUNNEL_STREAM_FAILED, Err: err}
	}
	return nil
}

// RelayChannel accepts one admitted direct-tcpip open and pumps it through
// the inner client until the channel ends. The inner dial happens BEFORE
// accepting so failures map to a native-style SSH_OPEN_CONNECT_FAILED
// rejection. Blocks the caller.
func (t *SessionTransport) RelayChannel(newCh ssh.NewChannel) {
	inner, _, err := t.client.OpenChannel("direct-tcpip", newCh.ExtraData())
	if err != nil {
		_ = newCh.Reject(ssh.ConnectionFailed, sanitizeConnectError(err))
		return
	}
	ch, _, err := newCh.Accept()
	if err != nil {
		_ = inner.Close()
		return
	}
	relayChannels(ch, inner)
}

// RelayGlobalRequest forwards tcpip-forward/cancel-tcpip-forward to the
// inner client. The reply payload (e.g. the bound port for port 0 requests)
// is passed through verbatim.
func (t *SessionTransport) RelayGlobalRequest(reqType string, wantReply bool, payload []byte) (bool, []byte) {
	ok, reply, err := t.client.SendRequest(reqType, wantReply, payload)
	if err != nil {
		t.log.Debug("global request relay failed", slog.String("request_type", reqType), slog.String("detail", err.Error()))
		return false, nil
	}
	return ok, reply
}

// Close tears down the child process and every bridge/relay goroutine.
// Idempotent; safe to call from multiple paths.
func (t *SessionTransport) Close() {
	t.closeOnce.Do(func() {
		if t.client != nil {
			_ = t.client.Close()
		}
		if t.innerConn != nil {
			_ = t.innerConn.Close()
		}
		if t.proc != nil {
			_ = terminateProcess(t.proc, t.f.ShutdownGrace)
			t.proc.StdoutDrained()
		}
		secretbox.BestEffortWipe(t.credential.Token)
		if t.f.Registry != nil && t.registryID != uuid.Nil {
			t.f.Registry.Remove(t.registryID)
		}
		done := make(chan struct{})
		go func() {
			t.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.log.Debug("transport close timed out waiting for relays")
		}
	})
}

func (t *SessionTransport) recheckAfterFailure(ctx context.Context, code string) {
	if t.f.Rechecker != nil && (code == core.TUNNEL_CODER_EXITED || code == core.TUNNEL_START_TIMEOUT) {
		t.f.Rechecker.RecheckAfterFailure(ctx, t.credential.AccountID, t.credential.Generation)
	}
}

func (t *SessionTransport) fail(channel ssh.Channel, message, code string, err error) error {
	_, _ = channel.Stderr().Write([]byte(message + "\r\n"))
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 255}))
	_ = channel.CloseWrite()
	return &StartError{Code: code, Err: err}
}

// relayChannels pumps one channel pair to completion with half-close
// propagation: EOF on one side CloseWrites the other, and both channels are
// closed once both directions finish.
func relayChannels(a, b ssh.Channel) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		_ = b.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		_ = a.CloseWrite()
	}()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

// sanitizeConnectError reduces an inner dial failure to a short single-line
// message safe to send to the client (no tokens, no response bodies).
func sanitizeConnectError(err error) string {
	msg := strings.ReplaceAll(err.Error(), "\n", " ")
	msg = strings.ReplaceAll(msg, "\r", " ")
	if len(msg) > 200 {
		msg = msg[:200]
	}
	if msg == "" {
		return "connect failed"
	}
	return "connect failed: " + msg
}
