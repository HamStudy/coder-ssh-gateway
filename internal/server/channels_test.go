package server_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/config"
	"github.com/taxilian/coder-ssh-gateway/internal/core"
	"github.com/taxilian/coder-ssh-gateway/internal/server"
)

// fakeTunnelCall is one recorded TunnelStarter invocation.
type fakeTunnelCall struct {
	Route      core.Route
	Generation int64
	HasToken   bool
}

// fakeTunnelStarter records every Start call and writes a marker into the
// accepted channel. T18 swaps in the real child-process starter.
type fakeTunnelStarter struct {
	mu     sync.Mutex
	calls  []fakeTunnelCall
	marker string
	err    error
	gate   chan struct{} // non-nil: Start blocks until closed or ctx done
}

func newFakeTunnelStarter(marker string) *fakeTunnelStarter {
	return &fakeTunnelStarter{marker: marker}
}

func (f *fakeTunnelStarter) Start(ctx context.Context, ch ssh.Channel, rt core.Route, snap core.CredentialSnapshot) error {
	f.mu.Lock()
	f.calls = append(f.calls, fakeTunnelCall{
		Route:      rt,
		Generation: snap.Generation,
		HasToken:   len(snap.Token) > 0,
	})
	marker := f.marker
	err := f.err
	gate := f.gate
	f.mu.Unlock()

	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil
		}
	}
	if err != nil {
		return err
	}
	if marker != "" {
		if _, werr := ch.Write([]byte(marker)); werr != nil {
			return werr
		}
	}
	return nil
}

func (f *fakeTunnelStarter) recorded() []fakeTunnelCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeTunnelCall(nil), f.calls...)
}

// openDirectTCPIP opens a direct-tcpip channel with an explicit payload so
// tests control the destination port and can send malformed payloads.
func openDirectTCPIP(client *ssh.Client, host string, port uint32) (ssh.Channel, <-chan *ssh.Request, error) {
	payload := ssh.Marshal(&struct {
		DestAddr string
		DestPort uint32
		OrigAddr string
		OrigPort uint32
	}{host, port, "198.51.100.7", 43210})
	return client.OpenChannel("direct-tcpip", payload)
}

func openChannelReason(err error) (ssh.RejectionReason, bool) {
	var openErr *ssh.OpenChannelError
	if !errors.As(err, &openErr) {
		return 0, false
	}
	return openErr.Reason, true
}

func channelAuditHasDetail(f *gwFixture, detail string) bool {
	for _, ev := range f.auditEvents(server.EventTypeChannelOpen) {
		if ev.DetailCode == detail {
			return true
		}
	}
	return false
}

func swapHandler(status *atomic.Int32) http.Handler {
	ok := coderOKHandler(testCoderUserID)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s := status.Load(); s != 200 {
			w.WriteHeader(int(s))
			return
		}
		ok.ServeHTTP(w, r)
	})
}

// Full path: authenticated transport client opens a valid direct-tcpip
// channel; the fake starter receives channel+route+credential snapshot and
// its marker bytes come back through the channel (§19.1, §19.2).
func TestDirectTCPIPFullPath(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, nil)
	defer ts.shutdown(t)

	client, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	defer client.Close()

	ch, _, err := openDirectTCPIP(client, "dev", 22)
	if err != nil {
		t.Fatalf("direct-tcpip open: %v", err)
	}
	defer ch.Close()

	marker := make([]byte, len("TUNNEL-OK"))
	if _, err := io.ReadFull(ch, marker); err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if string(marker) != "TUNNEL-OK" {
		t.Errorf("marker = %q, want TUNNEL-OK", marker)
	}

	calls := f.starter.recorded()
	if len(calls) != 1 {
		t.Fatalf("starter calls = %d, want 1", len(calls))
	}
	call := calls[0]
	if call.Route.WorkspaceHost != "dev" {
		t.Errorf("WorkspaceHost = %q", call.Route.WorkspaceHost)
	}
	if call.Route.RequestedPort != 22 {
		t.Errorf("RequestedPort = %d", call.Route.RequestedPort)
	}
	if call.Generation != 1 {
		t.Errorf("snapshot generation = %d, want 1", call.Generation)
	}
	if !call.HasToken {
		t.Error("snapshot must carry the decrypted token to the starter")
	}

	// §19.10: channel requests are drained; WantReply gets a false reply.
	ok, err := ch.SendRequest("pubkey-req@openssh.com", true, nil)
	if err != nil {
		t.Fatalf("channel request: %v", err)
	}
	if ok {
		t.Error("channel request must be answered false (§19.10 drain)")
	}

	// Accepted channel audited with the log-safe display target (§34.3).
	waitFor(t, 3*time.Second, func() bool {
		for _, ev := range f.auditEvents(server.EventTypeChannelOpen) {
			if ev.Result == "success" && ev.Target == "dev" {
				return true
			}
		}
		return false
	})

	// After the starter returns and the channel closes, every channel-scope
	// semaphore is released (§19.1 step 15).
	ch.Close()
	waitFor(t, 3*time.Second, func() bool {
		u := ts.counters.Usage()
		if u.CoderProcesses != 0 {
			return false
		}
		for _, n := range u.Channels {
			if n != 0 {
				return false
			}
		}
		for _, n := range u.ChannelAccounts {
			if n != 0 {
				return false
			}
		}
		return true
	})
}

// §8.3/§8.5 rejection matrix for transport mode: each disallowed open maps
// to the correct RFC 4254 reason and (where routed) the stable detail code.
func TestTransportChannelRejectionMatrix(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, nil)
	defer ts.shutdown(t)

	client, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	defer client.Close()

	t.Run("port not 22", func(t *testing.T) {
		_, _, err := openDirectTCPIP(client, "dev", 2222)
		reason, ok := openChannelReason(err)
		if !ok || reason != ssh.Prohibited {
			t.Errorf("err = %v, want OpenChannelError Prohibited", err)
		}
		if !channelAuditHasDetail(f, core.ROUTE_PORT_DENIED) {
			t.Error("missing audit with ROUTE_PORT_DENIED")
		}
	})

	t.Run("IP literal denied", func(t *testing.T) {
		_, _, err := openDirectTCPIP(client, "192.0.2.1", 22)
		reason, ok := openChannelReason(err)
		if !ok || reason != ssh.Prohibited {
			t.Errorf("err = %v, want OpenChannelError Prohibited", err)
		}
		if !channelAuditHasDetail(f, core.ROUTE_NAME_INVALID) {
			t.Error("missing audit with ROUTE_NAME_INVALID")
		}
	})

	t.Run("too many labels", func(t *testing.T) {
		_, _, err := openDirectTCPIP(client, "a.b.c.d", 22)
		reason, ok := openChannelReason(err)
		if !ok || reason != ssh.Prohibited {
			t.Errorf("err = %v, want OpenChannelError Prohibited", err)
		}
		if !channelAuditHasDetail(f, core.ROUTE_NAME_INVALID) {
			t.Error("missing audit with ROUTE_NAME_INVALID")
		}
	})

	t.Run("malformed payload", func(t *testing.T) {
		// String header claims 9 bytes, only 1 follows: ssh.Unmarshal fails.
		_, _, err := client.OpenChannel("direct-tcpip", []byte{0, 0, 0, 9, 'x'})
		reason, ok := openChannelReason(err)
		if !ok || reason != ssh.Prohibited {
			t.Errorf("err = %v, want OpenChannelError Prohibited", err)
		}
		if !channelAuditHasDetail(f, core.ROUTE_INVALID_PAYLOAD) {
			t.Error("missing audit with ROUTE_INVALID_PAYLOAD")
		}
	})

	t.Run("session rejected as policy", func(t *testing.T) {
		_, _, err := client.OpenChannel("session", nil)
		reason, ok := openChannelReason(err)
		if !ok || reason != ssh.Prohibited {
			t.Errorf("err = %v, want OpenChannelError Prohibited", err)
		}
	})

	t.Run("forwarded-tcpip unknown type", func(t *testing.T) {
		_, _, err := client.OpenChannel("forwarded-tcpip", nil)
		reason, ok := openChannelReason(err)
		if !ok || reason != ssh.UnknownChannelType {
			t.Errorf("err = %v, want OpenChannelError UnknownChannelType", err)
		}
	})

	t.Run("vendor type unknown", func(t *testing.T) {
		_, _, err := client.OpenChannel("foo@bar", nil)
		reason, ok := openChannelReason(err)
		if !ok || reason != ssh.UnknownChannelType {
			t.Errorf("err = %v, want OpenChannelError UnknownChannelType", err)
		}
	})

	if got := len(f.starter.recorded()); got != 0 {
		t.Errorf("starter calls = %d, want 0 after all rejections", got)
	}
}

// §8.5: an exhausted per-connection channel semaphore maps to
// ResourceShortage and audits TUNNEL_LIMIT_REACHED.
func TestChannelLimitResourceShortage(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	blocking := newFakeTunnelStarter("")
	blocking.gate = make(chan struct{})

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		lc.Limits.ChannelsPerConnection = 1
		sc.TunnelStarter = blocking
	})
	defer ts.shutdown(t)
	defer close(blocking.gate)

	client, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	defer client.Close()

	ch1, _, err := openDirectTCPIP(client, "dev", 22)
	if err != nil {
		t.Fatalf("first direct-tcpip open: %v", err)
	}
	defer ch1.Close()

	// First channel holds the only slot while its starter is blocked.
	waitFor(t, 3*time.Second, func() bool { return len(blocking.recorded()) == 1 })

	_, _, err = openDirectTCPIP(client, "dev", 22)
	reason, ok := openChannelReason(err)
	if !ok || reason != ssh.ResourceShortage {
		t.Errorf("err = %v, want OpenChannelError ResourceShortage", err)
	}
	if !channelAuditHasDetail(f, core.TUNNEL_LIMIT_REACHED) {
		t.Error("missing audit with TUNNEL_LIMIT_REACHED")
	}
}

// §19.9(a): credential invalidated between auth and channel open → channel
// rejected AND the entire outer transport is closed.
func TestStaleCredentialInvalidClosesTransport(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, nil)
	defer ts.shutdown(t)

	client, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	defer client.Close()

	if err := f.store.MarkCredentialInvalid(context.Background(), f.acct.ID, 1, "test-invalidation"); err != nil {
		t.Fatalf("MarkCredentialInvalid: %v", err)
	}

	_, _, err = openDirectTCPIP(client, "dev", 22)
	reason, ok := openChannelReason(err)
	if !ok || reason != ssh.Prohibited {
		t.Errorf("err = %v, want OpenChannelError Prohibited", err)
	}

	// The server must close the whole outer transport (§19.9). Per the T15
	// mux-bug note, assert via Conn.Wait, never SendRequest-after-close.
	waitErr := make(chan error, 1)
	go func() { waitErr <- client.Conn.Wait() }()
	select {
	case <-waitErr:
	case <-time.After(3 * time.Second):
		t.Fatal("outer transport not closed after stale invalid credential")
	}
}

// §19.9(b): credential replaced with a NEWER VALID generation between auth
// and channel open → the channel proceeds with the new snapshot.
func TestStaleCredentialNewerValidGenerationProceeds(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, nil)
	defer ts.shutdown(t)

	client, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	defer client.Close()

	_, err = f.store.ReplaceCredential(context.Background(), core.ReplaceCredentialRequest{
		AccountID:          f.acct.ID,
		ExpectedGeneration: 1,
		Token:              []byte("wire-token-transport-renewed-02"),
		Identity: core.CoderIdentity{
			ID:       testCoderUserID,
			Username: "taxilian",
			Status:   "active",
		},
	})
	if err != nil {
		t.Fatalf("ReplaceCredential: %v", err)
	}

	ch, _, err := openDirectTCPIP(client, "dev", 22)
	if err != nil {
		t.Fatalf("direct-tcpip with newer generation: %v", err)
	}
	defer ch.Close()

	calls := f.starter.recorded()
	if len(calls) != 1 {
		t.Fatalf("starter calls = %d, want 1", len(calls))
	}
	if calls[0].Generation != 2 {
		t.Errorf("starter saw generation = %d, want 2 (newer snapshot)", calls[0].Generation)
	}
}

// §19.9(c) + §11.4: Coder unavailable during channel-open revalidation →
// ConnectionFailed, transport stays open, retry succeeds after recovery.
func TestRevalidationCoderUnavailableKeepsTransport(t *testing.T) {
	defer leakCheck(t)

	var status atomic.Int32
	status.Store(200)
	handler := swapHandler(&status)

	f := newFixture(t, handler)
	defer f.close(t)
	// Immediate-expiry verifier cache so channel-open revalidation always
	// reaches the (flipped) HTTP handler.
	f.rebuildVerifier(t, time.Nanosecond)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		sc.CacheTTL = time.Nanosecond
	})
	defer ts.shutdown(t)

	client, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	defer client.Close()

	status.Store(503)

	_, _, err = openDirectTCPIP(client, "dev", 22)
	reason, ok := openChannelReason(err)
	if !ok || reason != ssh.ConnectionFailed {
		t.Errorf("err = %v, want OpenChannelError ConnectionFailed", err)
	}
	if !channelAuditHasDetail(f, core.AUTH_CODER_UNAVAILABLE) {
		t.Error("missing audit with AUTH_CODER_UNAVAILABLE")
	}

	// Transport NOT closed (§11.4: unavailable is not a credential failure).
	alive, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
	if err != nil || !alive {
		t.Errorf("transport must stay open after 503 revalidation (alive=%v, err=%v)", alive, err)
	}

	// Recovery: ControlPlaneUnavailable is never cached (§11.5), so the
	// retry re-validates over HTTP and proceeds.
	status.Store(200)
	ch, _, err := openDirectTCPIP(client, "dev", 22)
	if err != nil {
		t.Fatalf("retry after recovery: %v", err)
	}
	ch.Close()
}

// Maintenance mode keeps rejecting every channel type until T21 lands.
func TestMaintenanceChannelsStillRejected(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)

	ts := startTestServer(t, f, nil)
	defer ts.shutdown(t)

	client, err := dialGateway(ts.addr(), "auth", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("maintenance auth: %v", err)
	}
	defer client.Close()

	for _, chType := range []string{"session", "direct-tcpip"} {
		_, _, err := client.OpenChannel(chType, nil)
		reason, ok := openChannelReason(err)
		if !ok || reason != ssh.Prohibited {
			t.Errorf("%s: err = %v, want OpenChannelError Prohibited", chType, err)
		}
	}
}
