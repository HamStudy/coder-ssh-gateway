package coderapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
)

var errOversizedBody = errors.New("response body exceeds 1 MiB limit")

// Verifier validates Coder session tokens against a single deployment's
// /api/v2/users/me endpoint (§11.1). It is safe for concurrent use.
type Verifier struct {
	deployment core.Deployment
	client     *http.Client
	opts       Options
}

// New constructs a Verifier. The deployment's CoderURL must be non-nil.
func New(dep core.Deployment, opts Options) (*Verifier, error) {
	if dep.CoderURL == nil {
		return nil, errors.New("coderapi: deployment CoderURL is nil")
	}
	client, err := NewHTTPClient(opts)
	if err != nil {
		return nil, err
	}
	return &Verifier{deployment: dep, client: client, opts: opts}, nil
}

type usersMeReply struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Status   string `json:"status"`
}

// Verify exchanges token for the authenticated Coder identity. The token
// buffer is wiped before Verify returns. All failures are classified as
// *core.CredentialError per §11.4; token and response body bytes never appear
// in returned errors.
func (v *Verifier) Verify(ctx context.Context, token []byte) (core.CoderIdentity, error) {
	var ident core.CoderIdentity
	if len(token) == 0 {
		return ident, credErr(core.CredentialInvalid, 0, false, core.AUTH_CREDENTIAL_UNAUTHORIZED,
			errors.New("empty token"))
	}

	// Copy so the wipe below cannot corrupt the caller's buffer mid-request,
	// and so the transient string conversion uses memory we control.
	local := bytes.Clone(token)
	defer func() {
		for i := range local {
			local[i] = 0
		}
	}()

	endpoint := v.deployment.CoderURL.JoinPath("/api/v2/users/me").String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ident, credErr(core.ControlPlaneIncompatible, 0, false, core.AUTH_CODER_INCOMPATIBLE,
			fmt.Errorf("build request: %w", err))
	}
	req.Header.Set("Coder-Session-Token", string(local))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", v.opts.userAgent())
	for name, values := range v.opts.Headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return ident, classifyTransport(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Drain (bounded) so the connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return ident, classifyStatus(resp.StatusCode)
	}

	body, err := readCapped(resp.Body)
	if err != nil {
		return ident, malformedReply(resp.StatusCode, err)
	}

	var reply usersMeReply
	if err := json.Unmarshal(body, &reply); err != nil {
		return ident, malformedReply(resp.StatusCode, fmt.Errorf("decode users/me: %w", err))
	}
	id, err := uuid.Parse(strings.TrimSpace(reply.ID))
	if err != nil || id == uuid.Nil {
		return ident, malformedReply(resp.StatusCode, errors.New("users/me id is not a nonzero UUID"))
	}

	ident.ID = id
	ident.Username = reply.Username
	ident.Status = reply.Status
	return ident, nil
}

// UUID to equal want (§11.3 expected identity match). A mismatch returns
// *core.CredentialError with Kind CredentialWrongIdentity.
func (v *Verifier) VerifyIdentity(ctx context.Context, token []byte, want uuid.UUID) error {
	ident, err := v.Verify(ctx, token)
	if err != nil {
		return err
	}
	if ident.ID != want {
		return credErr(core.CredentialWrongIdentity, http.StatusOK, false,
			core.AUTH_WRONG_CODER_IDENTITY, nil)
	}
	return nil
}

// readCapped reads up to MaxBodyBytes+1 bytes and reports errOversizedBody
// when the limit is exceeded, so oversize is detected even without a
// Content-Length header.
func readCapped(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, MaxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if len(body) > MaxBodyBytes {
		return nil, errOversizedBody
	}
	return body, nil
}
