package coderapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/google/uuid"
)

// WorkspacesPageLimit is how many workspaces one listing request fetches
// before client-side owner filtering. The enrollment hint only needs a
// handful of names; 100 keeps the reply bounded while covering realistic
// personal workspace counts.
const WorkspacesPageLimit = 100

type workspacesPage struct {
	Workspaces []struct {
		Name    string `json:"name"`
		OwnerID string `json:"owner_id"`
	} `json:"workspaces"`
}

// ListOwnedWorkspaces fetches the first page of workspaces and returns the
// names owned by owner, capped at limit, plus how many owned workspaces the
// page contained (so callers can say "and N more"). Best-effort by contract:
// callers treat any error as "skip the hint" — never as an enrollment
// failure. The token buffer is wiped before return.
func (v *Verifier) ListOwnedWorkspaces(ctx context.Context, token []byte, owner uuid.UUID, limit int) ([]string, int, error) {
	local := bytes.Clone(token)
	defer func() {
		for i := range local {
			local[i] = 0
		}
	}()

	q := url.Values{"limit": {fmt.Sprintf("%d", WorkspacesPageLimit)}}
	endpoint := v.deployment.CoderURL.JoinPath("/api/v2/workspaces").String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
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
		return nil, 0, fmt.Errorf("list workspaces: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, 0, fmt.Errorf("list workspaces: status %d", resp.StatusCode)
	}

	body, err := readCapped(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("read workspaces: %w", err)
	}
	var page workspacesPage
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, 0, fmt.Errorf("decode workspaces: %w", err)
	}

	names := make([]string, 0, limit)
	owned := 0
	for _, ws := range page.Workspaces {
		id, err := uuid.Parse(ws.OwnerID)
		if err != nil || id != owner || ws.Name == "" {
			continue
		}
		owned++
		if len(names) < limit {
			names = append(names, ws.Name)
		}
	}
	return names, owned, nil
}
