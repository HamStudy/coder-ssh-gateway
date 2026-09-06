// Package maintenance implements the §14 restricted maintenance session: a
// single `session` channel on `auth@` connections running a built-in,
// line-oriented credential-repair interface plus the exact-match exec
// commands status/renew/clear/help. No OS PTY, no shell, and no subprocess
// is ever involved (§14.2).
package maintenance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/secretbox"
	"github.com/HamStudy/coder-ssh-gateway/internal/sshauth"
	"github.com/HamStudy/coder-ssh-gateway/internal/store"
)

// exec command names, matched byte-exactly against the exec payload (§14.2 —
// no shell, no concatenation).
const (
	cmdStatus = "status"
	cmdRenew  = "renew"
	cmdClear  = "clear"
	cmdHelp   = "help"
)

// maxExecPayloadBytes bounds the raw exec request payload; the four
// §14.2 commands are a handful of bytes, so anything larger is unknown.
const maxExecPayloadBytes = 4096

// statusProbeTimeout bounds the §14.4 control-plane reachability probe.
const statusProbeTimeout = 2 * time.Second

const (
	defaultSessionTimeout = 5 * time.Minute
	defaultInputTimeout   = 2 * time.Minute
	defaultMaxAttempts    = sshauth.DefaultMaxRenewalAttempts
)

var (
	// errUnknownCommand maps any non-exact-match exec payload to the §14.2
	// "unknown command" rejection (exit-status 1, nothing executed).
	errUnknownCommand = errors.New("maintenance: unknown command")
	// errNoCommand marks a channel whose client never sent shell/exec.
	errNoCommand = errors.New("maintenance: channel closed before shell/exec")
	// errNegotiationTimeout is the §27 inactivity timeout awaiting shell/exec.
	errNegotiationTimeout = errors.New("maintenance: timed out waiting for shell/exec")
	// errAttemptsExhausted ends the interactive retry loop (bounded §14.3 retry).
	errAttemptsExhausted = errors.New("maintenance: token attempts exhausted")
)

// Store is the narrow store subset the maintenance session needs (§14).
// *store.Store satisfies it.
type Store interface {
	GetAccount(id uuid.UUID) (core.Account, error)
	LoadCredential(ctx context.Context, accountID uuid.UUID) (core.CredentialSnapshot, error)
	ClearCredential(ctx context.Context, accountID uuid.UUID, expectedGeneration int64) error
}

// StatusVerifier is the narrow reachability probe used by `status` (§14.4):
// Verify is called with a deliberately invalid probe token, so any
// classified Coder answer (even a 401) proves reachability and only a
// transport-level failure (ControlPlaneUnavailable) means unreachable.
// *coderapi.Verifier satisfies it.
type StatusVerifier interface {
	Verify(ctx context.Context, token []byte) (core.CoderIdentity, error)
}

// Config carries the §28 maintenance timeouts and the §14.3 retry bound.
type Config struct {
	// SessionTimeout bounds the whole maintenance session. Zero selects 5m.
	SessionTimeout time.Duration
	// InputTimeout is the §27 inactivity bound awaiting shell/exec and the
	// §14.3 per-keystroke inactivity bound at the token prompt. Zero selects
	// 2m.
	InputTimeout time.Duration
	// MaxAttempts bounds invalid-candidate retries per session (§14.3).
	// <=0 selects sshauth.DefaultMaxRenewalAttempts.
	MaxAttempts int
}

func (c Config) sessionTimeout() time.Duration {
	if c.SessionTimeout > 0 {
		return c.SessionTimeout
	}
	return defaultSessionTimeout
}

func (c Config) inputTimeout() time.Duration {
	if c.InputTimeout > 0 {
		return c.InputTimeout
	}
	return defaultInputTimeout
}

func (c Config) maxAttempts() int {
	if c.MaxAttempts > 0 {
		return c.MaxAttempts
	}
	return defaultMaxAttempts
}

// Handler runs the §14 maintenance session on one accepted `session`
// channel. It is wired into the server via ServerConfig.MaintenanceHandler.
type Handler struct {
	// Store provides account/credential reads and the §14.5 clear.
	Store Store
	// Renewal runs the shared §25.4 token replacement path (T20) via
	// ReplaceToken. Required for the interactive flow and `renew`.
	Renewal *sshauth.RenewalConfig
	// Verifier probes control-plane reachability for `status` (§14.4).
	// Nil reports "unknown".
	Verifier StatusVerifier
	// CoderURL is the deployment base URL rendered in the banner and
	// status; /cli-auth is derived from it.
	CoderURL string
	Config   Config
}

// Handle runs one maintenance session channel to completion (§27): request
// negotiation, command execution, exit-status delivery, CloseWrite. The
// caller (server dispatch) closes the channel and the outer transport after
// Handle returns (§14.3: a finished maintenance session always ends the
// connection).
func (h *Handler) Handle(ctx context.Context, channel ssh.Channel, requests <-chan *ssh.Request, accountID uuid.UUID) error {
	cfg := h.Config
	ctx, cancel := context.WithTimeout(ctx, cfg.sessionTimeout())
	defer cancel()

	mode, command, err := negotiate(ctx, channel, requests, cfg.inputTimeout())
	if err != nil {
		sendExitStatus(channel, 1)
		_ = channel.CloseWrite()
		return err
	}

	// After negotiation the request channel must never go unread (§19.10
	// applies to session channels too).
	go drainRequests(requests)

	var runErr error
	if mode == modeShell {
		runErr = h.runInteractive(ctx, channel, accountID, cfg)
	} else {
		runErr = h.runExec(ctx, channel, accountID, command, cfg)
	}

	status := uint32(0)
	if runErr != nil {
		status = 1
	}
	sendExitStatus(channel, status)
	_ = channel.CloseWrite()
	return runErr
}

type sessionMode int

const (
	modeShell sessionMode = iota + 1
	modeExec
)

type execRequest struct {
	Command string
}

// negotiate implements the §27/§14.2 request negotiation: at most one
// `shell` OR `exec` wins; `subsystem` is rejected; `pty-req` is acknowledged
// but no OS PTY is allocated; `env` and `window-change` are ignored; an
// inactivity timeout bounds the wait.
func negotiate(ctx context.Context, channel ssh.Channel, requests <-chan *ssh.Request, inputTimeout time.Duration) (sessionMode, string, error) {
	timer := time.NewTimer(inputTimeout)
	defer timer.Stop()
	reset := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(inputTimeout)
	}
	for {
		select {
		case req, ok := <-requests:
			if !ok {
				return 0, "", errNoCommand
			}
			reset()
			switch req.Type {
			case "pty-req":
				// §14.3: acknowledge so clients proceed to shell/exec; the
				// channel implements the terminal semantics in band.
				_ = req.Reply(true, nil)
			case "shell":
				_ = req.Reply(true, nil)
				return modeShell, "", nil
			case "exec":
				_ = req.Reply(true, nil)
				if len(req.Payload) > maxExecPayloadBytes {
					return modeExec, "", nil
				}
				var exec execRequest
				if err := ssh.Unmarshal(req.Payload, &exec); err != nil {
					return modeExec, "", nil
				}
				return modeExec, exec.Command, nil
			default:
				// subsystem, env, window-change, signal, ...: not part of the
				// maintenance interface (§14.2).
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		case <-timer.C:
			_, _ = io.WriteString(channel, "maintenance: no shell or exec request received; closing\r\n")
			return 0, "", errNegotiationTimeout
		case <-ctx.Done():
			return 0, "", ctx.Err()
		}
	}
}

// drainRequests answers every late channel request false until close; a
// second shell/exec (§27: at most one) is rejected here.
func drainRequests(requests <-chan *ssh.Request) {
	for req := range requests {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}

type exitStatusRequest struct {
	Status uint32
}

func sendExitStatus(channel ssh.Channel, status uint32) {
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{Status: status}))
}

// cliAuthURL renders the deployment /cli-auth URL, the only URL that may
// appear in maintenance user-facing text (§35).
func (h *Handler) cliAuthURL() string {
	base := strings.TrimRight(h.CoderURL, "/")
	if base == "" {
		return "your Coder deployment's /cli-auth page"
	}
	return base + "/cli-auth"
}

// abbrevUUID renders a bound Coder user UUID as the first 8 hex chars plus
// an ellipsis (§14.3/§14.4 — never the full internal ID).
func abbrevUUID(id uuid.UUID) string {
	s := id.String()
	if len(s) < 8 {
		return s + "…"
	}
	return s[:8] + "…"
}

func coderUserLine(acct core.Account) string {
	if acct.CoderUserID == nil {
		return "unbound"
	}
	name := acct.CachedUsername
	if name == "" {
		name = "unknown"
	}
	return fmt.Sprintf("%s (%s)", name, abbrevUUID(*acct.CoderUserID))
}

// credentialLabel renders the §14.3 banner credential field.
func credentialLabel(state core.CredentialState) string {
	if state == core.CredentialStateInvalid {
		return "invalid or expired"
	}
	return state.String()
}

func (h *Handler) loadAccountAndCredential(ctx context.Context, w io.Writer, accountID uuid.UUID) (core.Account, core.CredentialSnapshot, error) {
	acct, err := h.Store.GetAccount(accountID)
	if err != nil {
		_, _ = io.WriteString(w, "Account unavailable; contact the gateway administrator.\r\n")
		return core.Account{}, core.CredentialSnapshot{}, err
	}
	snap, err := h.Store.LoadCredential(ctx, accountID)
	if err != nil {
		_, _ = io.WriteString(w, "Credential store unavailable; try again later.\r\n")
		return core.Account{}, core.CredentialSnapshot{}, err
	}
	return acct, snap, nil
}

// runInteractive is the §14.3 shell flow: banner -> /cli-auth instruction ->
// hidden token prompt -> shared validate/store -> confirmation -> exit 0
// (the server then closes the outer transport).
func (h *Handler) runInteractive(ctx context.Context, channel ssh.Channel, accountID uuid.UUID, cfg Config) error {
	acct, snap, err := h.loadAccountAndCredential(ctx, channel, accountID)
	if err != nil {
		return err
	}
	defer secretbox.BestEffortWipe(snap.Token)

	fmt.Fprintf(channel, "Coder SSH Gateway credential maintenance\r\n\r\n")
	fmt.Fprintf(channel, "Gateway account: %s\r\n", acct.Label)
	fmt.Fprintf(channel, "Coder server:    %s\r\n", h.CoderURL)
	fmt.Fprintf(channel, "Coder user:      %s\r\n", coderUserLine(acct))
	fmt.Fprintf(channel, "Credential:      %s\r\n\r\n", credentialLabel(snap.State))
	fmt.Fprintf(channel, "Generate a new token at:\r\n%s\r\n\r\n", h.cliAuthURL())

	return h.renewLoop(ctx, channel, acct, snap.Generation, cfg)
}

// renewLoop is the shared §14.3 prompt/validate cycle behind both the
// interactive shell flow and `exec renew`: hidden input, bounded retry on
// rejected candidates, clean failure preserving the old credential when the
// control plane is unreachable.
func (h *Handler) renewLoop(ctx context.Context, channel ssh.Channel, account core.Account, generation int64, cfg Config) error {
	if h.Renewal == nil {
		_, _ = io.WriteString(channel, "Token renewal is not available on this gateway.\r\n")
		return errors.New("maintenance: renewal not configured")
	}
	pump := newBytePump(channel)
	for attempts := 1; ; attempts++ {
		_, _ = io.WriteString(channel, "Paste Coder token: ")
		line, err := pump.readLine(ctx, channel, cfg.inputTimeout())
		if err != nil {
			if errors.Is(err, ErrInputCancelled) {
				_, _ = io.WriteString(channel, "Cancelled.\r\n")
			}
			return err
		}

		_, err = h.Renewal.ReplaceToken(ctx, account, generation, line)
		secretbox.BestEffortWipe(line)
		if err == nil {
			// The replacement refreshed the cached identity; reload for the
			// confirmation message (§14.3 names the verified Coder user).
			username := account.CachedUsername
			if refreshed, rerr := h.Store.GetAccount(account.ID); rerr == nil && refreshed.CachedUsername != "" {
				username = refreshed.CachedUsername
			}
			if username == "" {
				username = "unknown"
			}
			fmt.Fprintf(channel, "Token verified for Coder user %s.\r\n", username)
			_, _ = io.WriteString(channel, "The gateway credential has been updated.\r\n")
			_, _ = io.WriteString(channel, "Reconnect to the workspace connection.\r\n")
			return nil
		}

		switch {
		case errors.Is(err, sshauth.ErrTokenRejected):
			if attempts >= cfg.maxAttempts() {
				_, _ = io.WriteString(channel, "Too many rejected tokens; closing.\r\n")
				return errAttemptsExhausted
			}
			fmt.Fprintf(channel, "Token not accepted. Copy the current token from\r\n%s and try again.\r\n\r\n", h.cliAuthURL())
		case errors.Is(err, sshauth.ErrCoderUnavailable):
			_, _ = io.WriteString(channel, "Coder control plane unavailable; your existing credential is unchanged.\r\n")
			return err
		case errors.Is(err, sshauth.ErrWrongUserToken):
			_, _ = io.WriteString(channel, "That token belongs to a different Coder account; closing.\r\n")
			return err
		case errors.Is(err, sshauth.ErrRenewalRateLimited):
			_, _ = io.WriteString(channel, "Too many renewal attempts; try again later.\r\n")
			return err
		default:
			_, _ = io.WriteString(channel, "Token renewal failed; your existing credential is unchanged.\r\n")
			return err
		}
	}
}

// runExec dispatches one exact-match §14.2 command. Anything else —
// including oversized or undecodable payloads — is "unknown command", exit
// 1. No payload is ever passed to a shell or subprocess.
func (h *Handler) runExec(ctx context.Context, channel ssh.Channel, accountID uuid.UUID, command string, cfg Config) error {
	switch command {
	case cmdStatus:
		return h.execStatus(ctx, channel, accountID)
	case cmdRenew:
		acct, snap, err := h.loadAccountAndCredential(ctx, channel, accountID)
		if err != nil {
			return err
		}
		defer secretbox.BestEffortWipe(snap.Token)
		fmt.Fprintf(channel, "Generate a new token at:\r\n%s\r\n\r\n", h.cliAuthURL())
		return h.renewLoop(ctx, channel, acct, snap.Generation, cfg)
	case cmdClear:
		return h.execClear(ctx, channel, accountID)
	case cmdHelp:
		writeHelp(channel)
		return nil
	default:
		_, _ = io.WriteString(channel, "unknown command\r\n")
		return errUnknownCommand
	}
}

func writeHelp(w io.Writer) {
	_, _ = io.WriteString(w, "Coder SSH Gateway credential maintenance\r\n\r\nAvailable commands:\r\n"+
		"  status   Show non-secret credential and deployment state\r\n"+
		"  renew    Replace the stored Coder credential by pasting a new token\r\n"+
		"  clear    Remove the stored credential (does not revoke it with Coder)\r\n"+
		"  help     Show this help\r\n")
}

// execStatus renders §14.4 nonsecret state only: never token fragments,
// ciphertext, key material, or full internal UUIDs.
func (h *Handler) execStatus(ctx context.Context, channel ssh.Channel, accountID uuid.UUID) error {
	acct, snap, err := h.loadAccountAndCredential(ctx, channel, accountID)
	if err != nil {
		return err
	}
	// LoadCredential decrypts the token for transport use; status never
	// prints it and wipes the snapshot copy immediately.
	defer secretbox.BestEffortWipe(snap.Token)

	fmt.Fprintf(channel, "Coder server:      %s\r\n", h.CoderURL)
	fmt.Fprintf(channel, "Account:           %s\r\n", acct.Label)
	fmt.Fprintf(channel, "Coder user:        %s\r\n", coderUserLine(acct))
	fmt.Fprintf(channel, "Credential state:  %s\r\n", snap.State)
	if snap.LastValidatedAt.IsZero() {
		_, _ = io.WriteString(channel, "Last validated:    never\r\n")
	} else {
		fmt.Fprintf(channel, "Last validated:    %s\r\n", snap.LastValidatedAt.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(channel, "Generation:        %d\r\n", snap.Generation)
	fmt.Fprintf(channel, "Control plane:     %s\r\n", h.probe(ctx))
	return nil
}

// probe answers the §14.4 reachability question with a bounded Verify round
// trip using a deliberately invalid token: a classified answer (including a
// 401) proves the control plane answered; only transport failure or a dead
// probe context means unreachable.
func (h *Handler) probe(ctx context.Context) string {
	if h.Verifier == nil {
		return "unknown"
	}
	probeCtx, cancel := context.WithTimeout(ctx, statusProbeTimeout)
	defer cancel()
	_, err := h.Verifier.Verify(probeCtx, []byte("coder-ssh-gateway-reachability-probe"))
	if err == nil {
		return "reachable"
	}
	if probeCtx.Err() != nil {
		return "unreachable"
	}
	if core.KindOf(err) == core.ControlPlaneUnavailable {
		return "unreachable"
	}
	return "reachable"
}

// execClear tombstones the stored credential (§14.5): generation CAS via
// ClearCredential, state becomes missing, and the message is explicit that
// Coder-side revocation is a separate, user-driven step.
func (h *Handler) execClear(ctx context.Context, channel ssh.Channel, accountID uuid.UUID) error {
	_, snap, err := h.loadAccountAndCredential(ctx, channel, accountID)
	if err != nil {
		return err
	}
	defer secretbox.BestEffortWipe(snap.Token)

	if err := h.Store.ClearCredential(ctx, accountID, snap.Generation); err != nil {
		if errors.Is(err, store.ErrGenerationConflict) {
			_, _ = io.WriteString(channel, "The credential changed concurrently; run clear again to retry.\r\n")
			return err
		}
		_, _ = io.WriteString(channel, "Could not clear the credential; try again later.\r\n")
		return err
	}
	_, _ = io.WriteString(channel, "The stored credential has been cleared; the next connection requires a new token.\r\n"+
		"This does NOT revoke the token with Coder — revoke it in the Coder web interface if necessary.\r\n")
	return nil
}
