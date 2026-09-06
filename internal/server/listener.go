// Package server implements the outer SSH listener: accept loop, admission
// control, per-connection SSH configuration, phase-aware deadlines, the §8.4
// global-request policy, and §8.3 channel dispatch (transport-mode
// direct-tcpip and maintenance-mode session in channels.go).
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/audit"
	"github.com/taxilian/coder-ssh-gateway/internal/limits"
	"github.com/taxilian/coder-ssh-gateway/internal/metrics"
	"github.com/taxilian/coder-ssh-gateway/internal/route"
	"github.com/taxilian/coder-ssh-gateway/internal/sshauth"
)

// ErrNilCounters is returned by New when no admission counters are provided;
// the server fails closed rather than running without admission control.
var ErrNilCounters = errors.New("server: counters are required")

// ErrNilRouteCodec / ErrNilTunnelStarter are returned by New when the
// direct-tcpip dispatch dependencies (T16) are missing; the server fails
// closed rather than accepting channels it cannot route or start.
var (
	ErrNilRouteCodec    = errors.New("server: route codec is required")
	ErrNilTunnelStarter = errors.New("server: tunnel starter is required")
)

const (
	defaultHandshakeTimeout   = 30 * time.Second
	defaultServerVersion      = "SSH-2.0-CoderSSHGW_0.1"
	defaultProxyHeaderTimeout = 5 * time.Second

	// defaultCacheTTL matches the §11.5 validation-cache default; after this
	// interval a credential snapshot is revalidated at channel open (§19.9).
	defaultCacheTTL = 15 * time.Second

	// proxyV1MaxLine is the strict length bound for a PROXY v1 header line
	// including the terminating CRLF (§31.4: strict length bounds).
	proxyV1MaxLine = 107
)

// ServerConfig carries everything New needs to build the immutable base SSH
// configuration once (§25.1) and to run the accept loop.
type ServerConfig struct {
	// HostSigners are the outer host keys (§30), loaded via LoadHostSigners.
	// At least one is required; the server never auto-generates keys.
	HostSigners []ssh.Signer
	// Auth is the sshauth callback configuration (T14).
	Auth sshauth.AuthConfig
	// Counters provides admission semaphores (T9).
	Counters *limits.Counters
	// PreAuthGate is the pre-auth source-IP rate gate (§20). Nil allows all.
	// It is consulted before any SSH bytes are read; false closes the conn.
	PreAuthGate func(ip string) bool
	// HandshakeTimeout bounds key exchange + authentication (§13.5).
	// Zero selects 30s.
	HandshakeTimeout time.Duration
	// TCPKeepalive sets SO_KEEPALIVE and its period on accepted sockets.
	// Zero leaves OS defaults.
	TCPKeepalive time.Duration
	// ServerVersion is the SSH identification string (§25.1). Zero selects
	// the package default.
	ServerVersion string
	// ProxyProtocol enables strict PROXY v1 header parsing before the SSH
	// handshake (§31.4). Default off; never auto-detected.
	ProxyProtocol bool
	// ProxyHeaderTimeout bounds the PROXY header read (§31.4 strict time
	// bounds). Zero selects min(5s, HandshakeTimeout).
	ProxyHeaderTimeout time.Duration
	// RouteCodec validates direct-tcpip targets (§17.5). Required (T16).
	RouteCodec route.RouteCodec
	// TunnelStarter starts workspace tunnels on accepted direct-tcpip
	// channels (§24.1). Required (T16); T17 provides the real starter.
	TunnelStarter TunnelStarter
	// WorkspaceSessionStarter bridges direct workspace `session` channels.
	// Nil rejects workspace sessions while preserving direct-tcpip operation.
	WorkspaceSessionStarter WorkspaceSessionStarter
	// CacheTTL bounds how long a credential snapshot's LastValidatedAt is
	// trusted before channel-open revalidation (§11.5, §19.9). Zero selects
	// 15s.
	CacheTTL time.Duration
	// MaintenanceHandler runs the §14 maintenance session on the single
	// admitted session channel of maintenance-mode connections (T21). Nil
	// keeps the reject-all behavior for maintenance mode (T15/T16 default).
	MaintenanceHandler MaintenanceHandler
	// Metrics receives connection/auth/channel/limit events (§34.2). Nil
	// selects a no-op recorder.
	Metrics metrics.Recorder
	// DrainPeriod is the §32 step-4 grace: on shutdown, active channels get
	// this long to finish before remaining connections are cancelled (which
	// triggers the tunnel supervisor's TERM/KILL ladder). Zero drains
	// immediately.
	DrainPeriod time.Duration
	Logger      *slog.Logger
	Audit       audit.Logger
}

// Server owns the immutable base ssh.ServerConfig and the accept loop.
// The base config is built once in New and never mutated (§9.4).
type Server struct {
	cfg  ServerConfig
	base *ssh.ServerConfig
	log  *slog.Logger
	rec  metrics.Recorder

	mu    sync.Mutex
	conns map[string]*sshauth.ConnState
	wg    sync.WaitGroup

	draining       atomic.Bool
	activeChannels atomic.Int64
}

// New validates cfg and builds the immutable base SSH configuration (§25.1).
func New(cfg ServerConfig) (*Server, error) {
	if len(cfg.HostSigners) == 0 {
		return nil, ErrNoHostKeys
	}
	if cfg.Counters == nil {
		return nil, ErrNilCounters
	}
	if cfg.RouteCodec == nil {
		return nil, ErrNilRouteCodec
	}
	if cfg.TunnelStarter == nil {
		return nil, ErrNilTunnelStarter
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = defaultCacheTTL
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = defaultHandshakeTimeout
	}
	if cfg.ServerVersion == "" {
		cfg.ServerVersion = defaultServerVersion
	}
	if cfg.ProxyHeaderTimeout <= 0 {
		cfg.ProxyHeaderTimeout = defaultProxyHeaderTimeout
		if cfg.ProxyHeaderTimeout > cfg.HandshakeTimeout {
			cfg.ProxyHeaderTimeout = cfg.HandshakeTimeout
		}
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	rec := cfg.Metrics
	if rec == nil {
		rec = metrics.NoopRecorder{}
	}

	s := &Server{
		cfg:   cfg,
		base:  buildBaseSSHConfig(cfg.ServerVersion, cfg.HostSigners),
		log:   log,
		rec:   rec,
		conns: make(map[string]*sshauth.ConnState),
	}
	for _, signer := range cfg.HostSigners {
		log.Info("host key loaded",
			slog.String("algorithm", signer.PublicKey().Type()),
			slog.String("fingerprint", ssh.FingerprintSHA256(signer.PublicKey())),
		)
	}
	return s, nil
}

// buildBaseSSHConfig implements §25.1 exactly: safe supported-algorithm sets
// (defensively copied), MaxAuthTries 6, configured server version, host
// signers, and NO top-level password/keyboard-interactive callbacks (§8.2).
func buildBaseSSHConfig(serverVersion string, signers []ssh.Signer) *ssh.ServerConfig {
	algorithms := ssh.SupportedAlgorithms()

	cfg := &ssh.ServerConfig{
		MaxAuthTries:  6,
		ServerVersion: serverVersion,
	}
	cfg.Config.KeyExchanges = append([]string(nil), algorithms.KeyExchanges...)
	cfg.Config.Ciphers = append([]string(nil), algorithms.Ciphers...)
	cfg.Config.MACs = append([]string(nil), algorithms.MACs...)
	cfg.PublicKeyAuthAlgorithms = append([]string(nil), algorithms.PublicKeyAuths...)

	for _, signer := range signers {
		cfg.AddHostKey(signer)
	}
	return cfg
}

// Serve accepts connections on ln until ctx is cancelled. The §32 shutdown
// sequence: stop accepting (listener close), mark draining (readiness goes
// false via Draining, new channel opens are rejected), permit active
// channels the DrainPeriod grace, then cancel remaining connection contexts
// (tunnel supervisors escalate TERM/KILL on their child process groups,
// T18) and wait for per-connection handlers. Serve returns nil on graceful
// shutdown.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
			s.draining.Store(true)
			s.waitDrain()
			s.closeAllConns()
		case <-done:
		}
	}()

	for {
		raw, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				s.wg.Wait()
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		if s.cfg.TCPKeepalive > 0 {
			if tc, ok := raw.(*net.TCPConn); ok {
				_ = tc.SetKeepAlive(true)
				_ = tc.SetKeepAlivePeriod(s.cfg.TCPKeepalive)
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(raw)
		}()
	}
}

// Draining reports whether the server is in the §32 drain phase; the health
// readiness check and channel admission consult it.
func (s *Server) Draining() bool { return s.draining.Load() }

// waitDrain permits active channels up to DrainPeriod to finish on their own
// before the caller cancels connection contexts. Polls at a coarse interval;
// zero DrainPeriod returns immediately.
func (s *Server) waitDrain() {
	if s.cfg.DrainPeriod <= 0 {
		return
	}
	deadline := time.Now().Add(s.cfg.DrainPeriod)
	for s.activeChannels.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := s.activeChannels.Load(); n > 0 {
		s.log.Info("drain period elapsed with active channels; cancelling connections",
			slog.Int64("active_channels", n),
			slog.Duration("drain_period", s.cfg.DrainPeriod),
		)
	}
}

// track/untrack maintain the live-connection registry used by shutdown.
func (s *Server) track(state *sshauth.ConnState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns[state.ID()] = state
}

func (s *Server) untrack(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, id)
}

func (s *Server) closeAllConns() {
	s.mu.Lock()
	states := make([]*sshauth.ConnState, 0, len(s.conns))
	for _, st := range s.conns {
		states = append(states, st)
	}
	s.mu.Unlock()
	for _, st := range states {
		_ = st.Close()
	}
}

// peerIP extracts the host portion of a socket peer address.
func peerIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// proxiedConn overrides RemoteAddr with the PROXY-asserted peer so ConnState
// and everything downstream (audit, logs) sees the asserted address (§31.4).
type proxiedConn struct {
	net.Conn
	asserted net.Addr
}

func (c *proxiedConn) RemoteAddr() net.Addr { return c.asserted }

// parseProxyV1 reads one PROXY protocol v1 header line from conn under strict
// time and length bounds (§31.4). It returns the asserted source address, or
// nil when the header is "PROXY UNKNOWN" (peer address stays the socket's).
func parseProxyV1(conn net.Conn, timeout time.Duration) (net.Addr, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("proxy header deadline: %w", err)
	}
	defer func() {
		_ = conn.SetReadDeadline(time.Time{})
	}()

	// Byte-at-a-time reads (no read-ahead buffer) so bytes belonging to the
	// following SSH handshake can never be consumed by the PROXY parser.
	var sb strings.Builder
	one := make([]byte, 1)
	for {
		if sb.Len() >= proxyV1MaxLine {
			return nil, errors.New("proxy header exceeds length bound")
		}
		if _, err := conn.Read(one); err != nil {
			return nil, fmt.Errorf("proxy header read: %w", err)
		}
		sb.WriteByte(one[0])
		if one[0] == '\n' {
			break
		}
	}
	line := sb.String()
	if !strings.HasSuffix(line, "\r\n") {
		return nil, errors.New("proxy header missing CRLF")
	}

	fields := strings.Fields(strings.TrimSuffix(line, "\r\n"))
	if len(fields) < 2 || fields[0] != "PROXY" {
		return nil, errors.New("not a PROXY v1 header")
	}
	switch fields[1] {
	case "UNKNOWN":
		return nil, nil
	case "TCP4", "TCP6":
	default:
		return nil, fmt.Errorf("unsupported proxy transport %q", fields[1])
	}
	if len(fields) != 6 {
		return nil, errors.New("proxy header field count")
	}

	srcIP, err := netip.ParseAddr(fields[2])
	if err != nil {
		return nil, fmt.Errorf("proxy source address: %w", err)
	}
	if _, err := netip.ParseAddr(fields[3]); err != nil {
		return nil, fmt.Errorf("proxy destination address: %w", err)
	}
	if fields[1] == "TCP4" && !srcIP.Is4() {
		return nil, errors.New("proxy TCP4 header with non-v4 source")
	}
	if fields[1] == "TCP6" && !srcIP.Is6() {
		return nil, errors.New("proxy TCP6 header with non-v6 source")
	}
	srcPort, err := parseProxyPort(fields[4])
	if err != nil {
		return nil, err
	}
	if _, err := parseProxyPort(fields[5]); err != nil {
		return nil, err
	}

	return &net.TCPAddr{IP: net.IP(srcIP.AsSlice()), Port: srcPort}, nil
}

func parseProxyPort(s string) (int, error) {
	port, err := strconv.Atoi(s)
	if err != nil || port < 0 || port > 65535 {
		return 0, fmt.Errorf("proxy port %q invalid", s)
	}
	return port, nil
}
