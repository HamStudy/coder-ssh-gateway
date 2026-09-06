package app

import (
	"errors"
	"fmt"
	"time"

	"github.com/HamStudy/coder-ssh-gateway/internal/coderapi"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/secretbox"
	"github.com/HamStudy/coder-ssh-gateway/internal/sshauth"
	"github.com/HamStudy/coder-ssh-gateway/internal/store"
)

func (c *cli) cmdAdminCredential(args []string) int {
	if len(args) == 0 {
		return c.adminUsageErr("credential")
	}
	switch args[0] {
	case "status":
		return c.credentialStatus(args[1:])
	case "set":
		return c.credentialSet(args[1:])
	case "clear":
		return c.credentialClear(args[1:])
	default:
		return c.adminUsageErr("credential")
	}
}

func (c *cli) credentialStatus(args []string) int {
	fs := c.newFlagSet("credential status")
	accountID := fs.String("account", "", "account UUID")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	id, err := parseUUIDFlag("--account", *accountID)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitUsage
	}
	_, st, code := c.loadConfigAndStore()
	if code != exitOK {
		return code
	}
	defer st.Close()
	if _, err := st.GetAccount(id); err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitError
	}
	rec, err := st.LoadCredentialRecord(id)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: loading credential: %v\n", err)
		return exitError
	}
	fmt.Fprintf(c.stdout, "account: %s\n", id)
	fmt.Fprintf(c.stdout, "state: %s\n", rec.State)
	fmt.Fprintf(c.stdout, "generation: %d\n", rec.Generation)
	if rec.LastValidatedAtMs != nil {
		fmt.Fprintf(c.stdout, "last_validated_at: %s\n", time.UnixMilli(*rec.LastValidatedAtMs).UTC().Format(time.RFC3339))
	}
	if rec.InvalidatedAtMs != nil {
		fmt.Fprintf(c.stdout, "invalidated_at: %s\n", time.UnixMilli(*rec.InvalidatedAtMs).UTC().Format(time.RFC3339))
	}
	if rec.LastErrorClass != nil {
		fmt.Fprintf(c.stdout, "last_error_class: %s\n", *rec.LastErrorClass)
	}
	return exitOK
}

// credentialSet validates a token against Coder and stores it encrypted.
// The token comes from --stdin or a hidden TTY prompt — NEVER argv (§29).
// Identity rules (§10.4/§10.5): a token for a different Coder UUID than the
// bound one is rejected outright; a first bind requires bind_on_first_token
// and an explicit "yes" confirmation.
func (c *cli) credentialSet(args []string) int {
	fs := c.newFlagSet("credential set")
	accountID := fs.String("account", "", "account UUID")
	useStdin := fs.Bool("stdin", false, "read the token from stdin instead of a hidden TTY prompt")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	id, err := parseUUIDFlag("--account", *accountID)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitUsage
	}
	cfg, st, code := c.loadConfigAndStore()
	if code != exitOK {
		return code
	}
	defer st.Close()

	acct, err := st.GetAccount(id)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitError
	}
	rec, err := st.LoadCredentialRecord(id)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: loading credential: %v\n", err)
		return exitError
	}

	rawToken, err := c.readSecret("Coder session token (input hidden): ", *useStdin)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: reading token: %v\n", err)
		return exitError
	}
	defer secretbox.BestEffortWipe(rawToken)
	token, err := sshauth.SanitizeToken(rawToken)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitError
	}
	defer secretbox.BestEffortWipe(token)

	dep, err := DeploymentFromConfig(cfg)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitError
	}
	vopts, err := VerifierOptionsFromConfig(cfg)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitError
	}
	verifier, err := coderapi.New(dep, vopts)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitError
	}
	ident, err := verifier.Verify(c.ctx, token)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: token validation failed: %v\n", credentialErrorForHumans(err))
		return exitError
	}

	if acct.CoderUserID != nil && *acct.CoderUserID != ident.ID {
		fmt.Fprintf(c.stderr, "error: token belongs to Coder user %q (%s), but account %s is bound to %s — rejected (a bound Coder identity cannot be changed this way)\n",
			ident.Username, ident.ID, acct.ID, *acct.CoderUserID)
		return exitError
	}
	if acct.CoderUserID == nil {
		if !acct.BindOnFirstToken {
			fmt.Fprintf(c.stderr, "error: account %s is unbound and bind_on_first_token is not set; refusing to bind\n", acct.ID)
			return exitError
		}
		prompt := fmt.Sprintf("Token belongs to Coder user %q (%s). Permanently bind account %s to this Coder user? Type 'yes' to confirm: ",
			ident.Username, ident.ID, acct.ID)
		confirmed, err := c.confirm(prompt, *useStdin)
		if err != nil {
			fmt.Fprintf(c.stderr, "error: reading confirmation: %v\n", err)
			return exitError
		}
		if !confirmed {
			fmt.Fprintf(c.stderr, "error: bind not confirmed; nothing stored\n")
			return exitError
		}
	}

	snap, err := st.ReplaceCredential(c.ctx, core.ReplaceCredentialRequest{
		AccountID:          id,
		ExpectedGeneration: rec.Generation,
		Token:              token,
		Identity:           ident,
	})
	if errors.Is(err, store.ErrGenerationConflict) {
		fmt.Fprintf(c.stderr, "error: credential changed concurrently; retry\n")
		return exitError
	}
	if errors.Is(err, store.ErrWrongIdentity) {
		fmt.Fprintf(c.stderr, "error: identity binding rejected: %v\n", err)
		return exitError
	}
	if err != nil {
		fmt.Fprintf(c.stderr, "error: storing credential: %v\n", err)
		return exitError
	}
	fmt.Fprintf(c.stdout, "credential stored for Coder user %q (account %s, generation %d)\n", ident.Username, id, snap.Generation)
	return exitOK
}

func (c *cli) credentialClear(args []string) int {
	fs := c.newFlagSet("credential clear")
	accountID := fs.String("account", "", "account UUID")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	id, err := parseUUIDFlag("--account", *accountID)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitUsage
	}
	_, st, code := c.loadConfigAndStore()
	if code != exitOK {
		return code
	}
	defer st.Close()
	if _, err := st.GetAccount(id); err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitError
	}
	rec, err := st.LoadCredentialRecord(id)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: loading credential: %v\n", err)
		return exitError
	}
	if err := st.ClearCredential(c.ctx, id, rec.Generation); err != nil {
		fmt.Fprintf(c.stderr, "error: clearing credential: %v\n", err)
		return exitError
	}
	fmt.Fprintf(c.stdout, "credential cleared for account %s (generation %d). This does NOT revoke the token with Coder; revoke it in the Coder web interface.\n", id, rec.Generation+1)
	return exitOK
}

// credentialErrorForHumans renders a classified coderapi failure without
// ever exposing token bytes or response bodies (§11.4, §29).
func credentialErrorForHumans(err error) error {
	var credErr *core.CredentialError
	if errors.As(err, &credErr) {
		switch credErr.Kind {
		case core.CredentialInvalid:
			return errors.New("coder rejected the token (401 unauthorized)")
		case core.CredentialForbidden:
			return errors.New("coder forbids this token (403)")
		case core.ControlPlaneUnavailable:
			return errors.New("coder control plane unreachable; token not stored, retry later")
		case core.ControlPlaneIncompatible:
			return errors.New("coder deployment incompatible (unexpected response)")
		case core.CredentialMalformedReply:
			return errors.New("coder returned a malformed identity reply")
		}
	}
	return err
}
