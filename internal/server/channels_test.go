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

	"github.com/HamStudy/coder-ssh-gateway/internal/config"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/limits"
	"github.com/HamStudy/coder-ssh-gateway/internal/metrics"
	"github.com/HamStudy/coder-ssh-gateway/internal/server"
	"github.com/HamStudy/coder-ssh-gateway/internal/tunnel"
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

// fakeTransportFactory stands in for the tunnel.TransportFactory: it records
// creation calls and every relayed channel/global request.
type fakeTransportFactory struct {
	mu        sync.Mutex
	created   int
	targets   []string
	withToken []bool
	tr        *fakeTransport
}

func newFakeTransportFactory() *fakeTransportFactory {
	f := &fakeTransportFactory{}
	f.tr = &fakeTransport{owner: f}
	return f
}

func (f *fakeTransportFactory) NewTransport(ctx context.Context, target string, snap core.CredentialSnapshot, out ssh.Conn) (tunnel.WorkspaceTransport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created++
	f.targets = append(f.targets, target)
	f.withToken = append(f.withToken, len(snap.Token) > 0)
	return f.tr, nil
}

type fakeTransport struct {
	owner    *fakeTransportFactory
	channels []string
	globals  []string
}

func (t *fakeTransport) recordChannel(typ string) {
	t.owner.mu.Lock()
	defer t.owner.mu.Unlock()
	t.channels = append(t.channels, typ)
}

func (t *fakeTransport) recordGlobal(typ string) {
	t.owner.mu.Lock()
	defer t.owner.mu.Unlock()
	t.globals = append(t.globals, typ)
}

func (t *fakeTransport) counts() (channels, globals int) {
	t.owner.mu.Lock()
	defer t.owner.mu.Unlock()
	return len(t.channels), len(t.globals)
}

func (t *fakeTransport) BridgeSession(ctx context.Context, ch ssh.Channel, requests <-chan *ssh.Request, queued []tunnel.QueuedSessionRequest) error {
	for req := range requests {
		accepted := req.Type == "shell" || req.Type == "exec" || req.Type == "pty-req"
		if req.WantReply {
			_ = req.Reply(accepted, nil)
		}
	}
	return nil
}

func (t *fakeTransport) RelayChannel(newCh ssh.NewChannel) {
	t.recordChannel(newCh.ChannelType())
	ch, requests, err := newCh.Accept()
	if err != nil {
		return
	}
	go func() {
		for req := range requests {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}()
	_, _ = io.Copy(io.Discard, ch)
	_ = ch.Close()
}

func (t *fakeTransport) RelayGlobalRequest(reqType string, wantReply bool, payload []byte) (bool, []byte) {
	t.recordGlobal(reqType)
	return true, nil
}

func (t *fakeTransport) Close() {}

// gatedTransportFactory wraps a fake factory whose NewTransport blocks on a
// gate: entry is signaled before blocking, so a test can hold the transport
// start in-flight and observe behavior at that exact point. Both waits
// escape on ctx cancellation so no goroutine outlives the connection.
type gatedTransportFactory struct {
	inner   *fakeTransportFactory
	entered chan struct{}
	gate    chan struct{}
}

func (g *gatedTransportFactory) NewTransport(ctx context.Context, target string, snap core.CredentialSnapshot, out ssh.Conn) (tunnel.WorkspaceTransport, error) {
	select {
	case g.entered <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case <-g.gate:
		return g.inner.NewTransport(ctx, target, snap, out)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *fakeTunnelStarter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
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

	waitFor(t, 5*time.Second, func() bool { return f.starter.count() == 1 })
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

// §8.3 dispatch matrix for workspace connections: arbitrary direct-tcpip
// targets relay through the connection transport, workspace:22 targets get
// jump tunnels, malformed payloads are rejected, and session channels
// multiplex concurrently under the channel limits (slots free on close).
func TestWorkspaceChannelDispatchMatrix(t *testing.T) {
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

	t.Run("arbitrary target relays through transport", func(t *testing.T) {
		channelsBefore, globalsBefore := f.transports.tr.counts()
		ch, _, err := openDirectTCPIP(client, "localhost", 8080)
		if err != nil {
			t.Fatalf("relay open: %v", err)
		}
		_ = ch.Close()
		waitFor(t, 5*time.Second, func() bool {
			channels, _ := f.transports.tr.counts()
			return channels > channelsBefore
		})
		if _, globals := f.transports.tr.counts(); globals != globalsBefore {
			t.Error("unexpected global request relay")
		}
	})

	t.Run("workspace target jumps", func(t *testing.T) {
		callsBefore := f.starter.count()
		ch, _, err := openDirectTCPIP(client, "dev", 22)
		if err != nil {
			t.Fatalf("jump open: %v", err)
		}
		_ = ch.Close()
		waitFor(t, 5*time.Second, func() bool { return f.starter.count() > callsBefore })
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

	t.Run("session reopens after close", func(t *testing.T) {
		ch, _, err := client.OpenChannel("session", nil)
		if err != nil {
			t.Fatalf("first session open: %v", err)
		}
		if ok, err := ch.SendRequest("shell", true, nil); err != nil || !ok {
			t.Errorf("shell request: ok=%v err=%v, want accepted", ok, err)
		}
		_ = ch.Close()
		waitFor(t, 5*time.Second, func() bool {
			u := ts.counters.Usage()
			return len(u.Channels) == 0 && len(u.ChannelAccounts) == 0
		})
		ch2, _, err := client.OpenChannel("session", nil)
		if err != nil {
			t.Fatalf("second session open after close: %v", err)
		}
		if ok, err := ch2.SendRequest("shell", true, nil); err != nil || !ok {
			t.Errorf("second shell request: ok=%v err=%v, want accepted", ok, err)
		}
		_ = ch2.Close()
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
}

// RFC 4254 §5 multiplexing on a workspace connection (sshd MaxSessions
// model): concurrent sessions coexist up to limits.channels_per_connection,
// and a closed session — cleanly or abruptly — frees its slot for the next
// open on the same connection.
func TestWorkspaceSessionMultiplexing(t *testing.T) {
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

	drainChannelSlots := func() {
		t.Helper()
		waitFor(t, 5*time.Second, func() bool {
			u := ts.counters.Usage()
			return len(u.Channels) == 0 && len(u.ChannelAccounts) == 0
		})
	}

	t.Run("two concurrent sessions both function", func(t *testing.T) {
		ch1, _, err := client.OpenChannel("session", nil)
		if err != nil {
			t.Fatalf("first session open: %v", err)
		}
		ch2, _, err := client.OpenChannel("session", nil)
		if err != nil {
			t.Fatalf("second concurrent session open: %v", err)
		}
		for i, ch := range []ssh.Channel{ch1, ch2} {
			if ok, err := ch.SendRequest("shell", true, nil); err != nil || !ok {
				t.Errorf("session %d shell request: ok=%v err=%v, want accepted", i+1, ok, err)
			}
		}
		_ = ch1.Close()
		_ = ch2.Close()
	})

	t.Run("reopen after clean close", func(t *testing.T) {
		ch, _, err := client.OpenChannel("session", nil)
		if err != nil {
			t.Fatalf("session open: %v", err)
		}
		if ok, err := ch.SendRequest("shell", true, nil); err != nil || !ok {
			t.Errorf("shell request: ok=%v err=%v, want accepted", ok, err)
		}
		_ = ch.Close()
		drainChannelSlots()
		ch2, _, err := client.OpenChannel("session", nil)
		if err != nil {
			t.Fatalf("session reopen after clean close: %v", err)
		}
		if ok, err := ch2.SendRequest("shell", true, nil); err != nil || !ok {
			t.Errorf("reopened shell request: ok=%v err=%v, want accepted", ok, err)
		}
		_ = ch2.Close()
	})
}

// Deterministic close-before-bridge slot release: with the transport start
// gated in-flight (factory entered, blocked), closing the outer session
// channel must release BOTH limiter slots before the transport ever starts,
// and a new session opens on the same connection once the gate lifts. The
// gate removes the race in an ungated close-after-open (the transport may
// already have started), so this runs standalone on a fresh connection —
// earlier sessions on a shared connection would keep the gate from ever
// being reached.
func TestWorkspaceSessionCloseBeforeBridgeReleasesSlots(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	gated := &gatedTransportFactory{
		inner:   newFakeTransportFactory(),
		entered: make(chan struct{}, 1),
		gate:    make(chan struct{}),
	}
	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		lc.Limits.ChannelsPerConnection = 1
		lc.Limits.ChannelsPerAccount = 1
		sc.WorkspaceTransports = gated
	})
	defer ts.shutdown(t)

	client, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	defer client.Close()

	ch, _, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("session open: %v", err)
	}
	// Wait until the transport start is in-flight: the factory has been
	// entered and is blocked, so the bridge cannot have started.
	select {
	case <-gated.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("transport factory never entered")
	}

	_ = ch.Close()
	// Both channel slots must release while the transport start is still
	// blocked — under caps of 1/1 a leaked slot would surface as a
	// non-empty usage map here.
	waitFor(t, 5*time.Second, func() bool {
		u := ts.counters.Usage()
		return len(u.Channels) == 0 && len(u.ChannelAccounts) == 0
	})

	close(gated.gate)

	ch2, _, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("session reopen after close-before-bridge: %v", err)
	}
	if ok, err := ch2.SendRequest("shell", true, nil); err != nil || !ok {
		t.Errorf("reopened shell request: ok=%v err=%v, want accepted", ok, err)
	}
	_ = ch2.Close()
}

// Over-cap concurrent sessions take the channel-limit path: ResourceShortage
// rejection before Accept, audit + log evidence, and the cap frees on close.
func TestWorkspaceSessionChannelLimit(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		lc.Limits.ChannelsPerConnection = 1
	})
	defer ts.shutdown(t)

	client, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	defer client.Close()

	ch1, _, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("first session open: %v", err)
	}
	if ok, err := ch1.SendRequest("shell", true, nil); err != nil || !ok {
		t.Errorf("shell request: ok=%v err=%v, want accepted", ok, err)
	}

	// The first session holds the only per-connection slot.
	_, _, err = client.OpenChannel("session", nil)
	reason, ok := openChannelReason(err)
	if !ok || reason != ssh.ResourceShortage {
		t.Errorf("second session err = %v, want OpenChannelError ResourceShortage", err)
	}
	if !channelAuditHasDetail(f, core.TUNNEL_LIMIT_REACHED) {
		t.Error("missing audit with TUNNEL_LIMIT_REACHED")
	}
	if !f.logs.contains("channel rejected at limit") {
		t.Error("missing channel-limit rejection log line")
	}

	// Closing the held session frees the slot for a new one.
	_ = ch1.Close()
	waitFor(t, 5*time.Second, func() bool {
		u := ts.counters.Usage()
		return len(u.Channels) == 0 && len(u.ChannelAccounts) == 0
	})
	ch2, _, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("session reopen after limit release: %v", err)
	}
	_ = ch2.Close()
}

// Simultaneous session opens race for the per-connection semaphore: exactly
// the cap (default fixture limits: 4) is accepted, the rest are rejected
// cleanly, and no slot leaks — a further open succeeds after one holder
// closes.
func TestWorkspaceSessionConcurrentOpenRace(t *testing.T) {
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

	type openResult struct {
		ch  ssh.Channel
		err error
	}
	const opens = 6
	results := make(chan openResult, opens)
	for i := 0; i < opens; i++ {
		go func() {
			ch, _, err := client.OpenChannel("session", nil)
			results <- openResult{ch: ch, err: err}
		}()
	}
	var accepted []ssh.Channel
	rejected := 0
	for i := 0; i < opens; i++ {
		r := <-results
		if r.err == nil {
			accepted = append(accepted, r.ch)
			continue
		}
		reason, ok := openChannelReason(r.err)
		if !ok || reason != ssh.ResourceShortage {
			t.Errorf("open err = %v, want OpenChannelError ResourceShortage", r.err)
		}
		rejected++
	}
	if len(accepted) != 4 || rejected != 2 {
		t.Fatalf("accepted = %d, rejected = %d, want 4/2 under cap 4", len(accepted), rejected)
	}
	for i, ch := range accepted {
		if ok, err := ch.SendRequest("shell", true, nil); err != nil || !ok {
			t.Errorf("accepted session %d shell: ok=%v err=%v, want accepted", i+1, ok, err)
		}
	}

	// One holder closes; the freed slot admits a new open (no slot leak).
	_ = accepted[0].Close()
	waitFor(t, 5*time.Second, func() bool {
		for _, n := range ts.counters.Usage().Channels {
			if n == 3 {
				return true
			}
		}
		return false
	})
	ch, _, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open after holder close: %v", err)
	}
	_ = ch.Close()
	for _, c := range accepted[1:] {
		_ = c.Close()
	}
}

// limitRejectionRecorder counts LimitRejection calls per reason code; the
// rest of the Recorder surface stays no-op.
type limitRejectionRecorder struct {
	metrics.NoopRecorder
	mu     sync.Mutex
	counts map[string]int
}

func newLimitRejectionRecorder() *limitRejectionRecorder {
	return &limitRejectionRecorder{counts: make(map[string]int)}
}

func (r *limitRejectionRecorder) LimitRejection(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counts[reason]++
}

func (r *limitRejectionRecorder) count(reason string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts[reason]
}

// assertSessionLimitRejection opens two sessions under the given limit
// overrides: the first is held, the second must be refused on the wire
// (ResourceShortage) with a TUNNEL_LIMIT_REACHED audit and exact
// per-reason LimitRejection counts (wantConn/wantAcct).
func assertSessionLimitRejection(t *testing.T, mutate func(lc *config.Config), wantConn, wantAcct int) {
	t.Helper()

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	rec := newLimitRejectionRecorder()
	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		sc.Metrics = rec
		mutate(lc)
	})
	defer ts.shutdown(t)

	client, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	defer client.Close()

	held, _, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("first session open: %v", err)
	}
	defer held.Close()

	_, _, err = client.OpenChannel("session", nil)
	reason, ok := openChannelReason(err)
	if !ok || reason != ssh.ResourceShortage {
		t.Fatalf("over-cap session err = %v, want OpenChannelError ResourceShortage", err)
	}
	if !channelAuditHasDetail(f, core.TUNNEL_LIMIT_REACHED) {
		t.Error("missing audit with TUNNEL_LIMIT_REACHED")
	}
	if got := rec.count(string(limits.ReasonChannelConn)); got != wantConn {
		t.Errorf("LimitRejection[%s] = %d, want %d", limits.ReasonChannelConn, got, wantConn)
	}
	if got := rec.count(string(limits.ReasonChannelAccount)); got != wantAcct {
		t.Errorf("LimitRejection[%s] = %d, want %d", limits.ReasonChannelAccount, got, wantAcct)
	}
}

// Never-silent rule for session cap rejections: the over-cap open must
// record LimitRejection with the exact reason code (channel_conn vs
// channel_account), mirroring the direct-tcpip admission paths.
func TestWorkspaceSessionLimitRejectionMetrics(t *testing.T) {
	defer leakCheck(t)

	t.Run("per-connection cap records channel_conn", func(t *testing.T) {
		assertSessionLimitRejection(t, func(lc *config.Config) {
			lc.Limits.ChannelsPerConnection = 1
			lc.Limits.ChannelsPerAccount = 8
		}, 1, 0)
	})

	t.Run("per-account cap records channel_account", func(t *testing.T) {
		assertSessionLimitRejection(t, func(lc *config.Config) {
			lc.Limits.ChannelsPerConnection = 4
			lc.Limits.ChannelsPerAccount = 1
		}, 0, 1)
	})
}

// Per-account session cap interplay: a session held on one connection
// consumes the account-wide channel slot, so a second connection's session
// open is refused until the first session closes.
func TestWorkspaceSessionPerAccountCap(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		lc.Limits.ChannelsPerConnection = 4
		lc.Limits.ChannelsPerAccount = 1
	})
	defer ts.shutdown(t)

	clientA, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("auth A: %v", err)
	}
	defer clientA.Close()
	clientB, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("auth B: %v", err)
	}
	defer clientB.Close()

	chA, _, err := clientA.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("connection A session open: %v", err)
	}
	if ok, err := chA.SendRequest("shell", true, nil); err != nil || !ok {
		t.Errorf("A shell request: ok=%v err=%v, want accepted", ok, err)
	}

	// B's open is refused: the per-account cap (1) is held by A's session
	// even though B's own per-connection budget is untouched.
	_, _, err = clientB.OpenChannel("session", nil)
	reason, ok := openChannelReason(err)
	if !ok || reason != ssh.ResourceShortage {
		t.Errorf("connection B session err = %v, want OpenChannelError ResourceShortage", err)
	}

	// Closing A's session frees the account slot; B opens immediately.
	_ = chA.Close()
	waitFor(t, 5*time.Second, func() bool {
		return len(ts.counters.Usage().ChannelAccounts) == 0
	})
	chB, _, err := clientB.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("connection B session open after A close: %v", err)
	}
	if ok, err := chB.SendRequest("shell", true, nil); err != nil || !ok {
		t.Errorf("B shell request: ok=%v err=%v, want accepted", ok, err)
	}
	_ = chB.Close()
}

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

	waitFor(t, 5*time.Second, func() bool { return f.starter.count() == 1 })
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
