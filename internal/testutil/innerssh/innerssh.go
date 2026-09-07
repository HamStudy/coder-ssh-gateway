// Package innerssh implements the fake inner SSH server used by the
// fake-coder test binary (internal/testutil/fake-coder) and by harness
// self-tests.
//
// The server mirrors the properties of a real Coder workspace agent SSH
// server that matter to the gateway (§6.3): no client authentication, an
// ephemeral in-memory host key, and a pure stdio transport with NO network
// listeners. It speaks just enough of the SSH protocol for integration
// tests: session channels with exec/shell requests, plus pty-req and
// window-change requests which are accepted and ignored.
//
// Behavior contract (deterministic, asserted by downstream tests):
//
//   - exec request "printf hello": writes "hello" then exit-status 0.
//   - other exec requests with payload P: write "ECHO:<P>" then exit-status 0.
//   - shell request: writes "FAKE-SHELL-READY\n", then echoes every line
//     received back to the sender; on channel EOF sends exit-status 0.
//   - pty-req / window-change: accepted (reply true), otherwise ignored.
//   - non-session channel types: rejected with ssh.UnknownChannelType.
//   - unknown session requests: rejected (reply false).
package innerssh

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ExecPrefix is prepended to the exec payload in the response.
const ExecPrefix = "ECHO:"

// ShellBanner is written immediately after a shell request is accepted.
const ShellBanner = "FAKE-SHELL-READY\n"

// pipeConn adapts an io.Reader/io.Writer pair to net.Conn so it can carry
// an SSH transport (ssh.NewServerConn / ssh.NewClientConn require net.Conn).
// Deadlines and Close are no-ops; callers own the underlying streams.
type pipeConn struct {
	io.Reader
	io.Writer
}

// NewConn wraps r/w as a net.Conn suitable for an SSH transport endpoint.
// The returned connection performs no buffering and no I/O of its own;
// closing it closes nothing on the underlying streams (callers own them).
func NewConn(r io.Reader, w io.Writer) net.Conn {
	return &pipeConn{Reader: r, Writer: w}
}

func (c *pipeConn) Close() error                     { return nil }
func (c *pipeConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *pipeConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *pipeConn) SetDeadline(time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return "pipe" }
func (a dummyAddr) String() string  { return string(a) }

// Serve runs one fake inner SSH server over the given streams until the
// client disconnects, the handshake fails, or ctx is cancelled.
//
// The host key is an ephemeral Ed25519 key generated in memory on every
// call; clients must use ssh.InsecureIgnoreHostKey (matching §6.3: the
// inner host key is not an independent authentication boundary).
//
// Serve blocks until the connection terminates and all channel handlers
// have returned. A nil error means the client disconnected cleanly.
func Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("innerssh: generate host key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		return fmt.Errorf("innerssh: host signer: %w", err)
	}

	config := &ssh.ServerConfig{
		// §6.3 parity: the real Coder agent SSH server performs no client
		// authentication; authorization already happened via Coder.
		NoClientAuth: true,
	}
	config.AddHostKey(signer)

	conn := NewConn(r, w)
	srvConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return fmt.Errorf("innerssh: handshake: %w", err)
	}

	// On cancellation, closing the SSH connection unblocks the channel
	// loops below; the underlying streams belong to the caller.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			srvConn.Close()
		case <-done:
		}
	}()

	reg := newForwardRegistry()
	defer reg.closeAll()
	go handleGlobalRequests(srvConn, reg, reqs)

	var wg sync.WaitGroup
	for newChan := range chans {
		switch newChan.ChannelType() {
		case "session":
			ch, requests, err := newChan.Accept()
			if err != nil {
				continue
			}
			wg.Go(func() {
				handleSession(srvConn, ch, requests)
			})
		case "direct-tcpip":
			wg.Go(func() {
				handleDirectTCPIP(newChan)
			})
		default:
			newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
	wg.Wait()

	if err := srvConn.Wait(); err != nil && !errors.Is(err, io.EOF) {
		// io.EOF is the normal client-disconnect outcome.
		return fmt.Errorf("innerssh: connection: %w", err)
	}
	return nil
}

// handleSession services one accepted session channel until it closes.
func handleSession(srvConn *ssh.ServerConn, ch ssh.Channel, requests <-chan *ssh.Request) {
	defer ch.Close()
	for req := range requests {
		switch req.Type {
		case "exec":
			var payload struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			if payload.Command == "printf hello" {
				io.WriteString(ch, "hello")
			} else if payload.Command == "exit 7" {
				sendExitStatus(ch, 7)
				return
			} else if payload.Command == "agent-ping" {
				summary, err := agentRequestIdentities(srvConn)
				if err != nil {
					fmt.Fprintf(ch, "%s%s", ExecPrefix, err.Error())
				} else {
					io.WriteString(ch, summary)
				}
			} else {
				fmt.Fprintf(ch, "%s%s", ExecPrefix, payload.Command)
			}
			sendExitStatus(ch, 0)
			return
		case "shell":
			req.Reply(true, nil)
			io.WriteString(ch, ShellBanner)
			echoLines(ch)
			sendExitStatus(ch, 0)
			return
		case "subsystem":
			var payload struct{ Subsystem string }
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				req.Reply(false, nil)
				continue
			}
			if payload.Subsystem != "sftp" {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			serveSFTP(ch)
			return
		case "env", "pty-req", "window-change", "signal", "auth-agent-req@openssh.com":
			// Accepted and ignored: the fake has no terminal, but real
			// clients routinely request a pty before shell sessions.
			req.Reply(true, nil)
		default:
			req.Reply(false, nil)
		}
	}
}

// echoLines copies every line read from ch back to ch until EOF.
func echoLines(ch ssh.Channel) {
	sc := bufio.NewScanner(ch)
	for sc.Scan() {
		fmt.Fprintln(ch, sc.Text())
	}
}

// sendExitStatus delivers the session exit-status request.
func sendExitStatus(ch ssh.Channel, status uint32) {
	ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
}
