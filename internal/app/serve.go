package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/taxilian/coder-ssh-gateway/internal/audit"
	"github.com/taxilian/coder-ssh-gateway/internal/coderapi"
	"github.com/taxilian/coder-ssh-gateway/internal/config"
	"github.com/taxilian/coder-ssh-gateway/internal/core"
	"github.com/taxilian/coder-ssh-gateway/internal/limits"
	"github.com/taxilian/coder-ssh-gateway/internal/maintenance"
	"github.com/taxilian/coder-ssh-gateway/internal/route"
	"github.com/taxilian/coder-ssh-gateway/internal/server"
	"github.com/taxilian/coder-ssh-gateway/internal/sshauth"
	"github.com/taxilian/coder-ssh-gateway/internal/store"
	"github.com/taxilian/coder-ssh-gateway/internal/tunnel"
)

// Built is the fully assembled gateway. T24 extension point: graceful drain,
// metrics, and health servers attach to this struct.
type Built struct {
	Config     *config.Config
	Logger     *slog.Logger
	Store      *store.Store
	Server     *server.Server
	Registry   *tunnel.Registry
	Deployment core.Deployment
	Verifier   *coderapi.Verifier

	auditLog *audit.JSONLFileLogger
}

// Build assembles the running system from a validated config: host keys,
// store + encryption, verifier, auth callbacks, renewal, tunnel starter,
// maintenance handler, and the SSH server.
func Build(cfg *config.Config, logger *slog.Logger) (*Built, error) {
	if logger == nil {
		var err error
		logger, err = audit.NewLogger(cfg.Observability.LogFormat, cfg.Observability.LogLevel)
		if err != nil {
			return nil, err
		}
	}
	signers, _, err := server.LoadHostSigners(cfg.SSH.HostKeys)
	if err != nil {
		return nil, fmt.Errorf("host keys: %w", err)
	}
	st, err := store.Open(cfg.State.Dir)
	if err != nil {
		return nil, fmt.Errorf("state store: %w", err)
	}
	st.SetKeyProvider(KeyProviderFromConfig(cfg, logger))
	dep, err := DeploymentFromConfig(cfg)
	if err != nil {
		st.Close()
		return nil, err
	}
	if err := st.EnsureDeployment(dep); err != nil {
		st.Close()
		return nil, fmt.Errorf("seeding deployment: %w", err)
	}

	vopts, err := VerifierOptionsFromConfig(cfg)
	if err != nil {
		st.Close()
		return nil, err
	}
	verifier, err := coderapi.New(dep, vopts)
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("coder verifier: %w", err)
	}
	cached := coderapi.NewCachedVerifier(dep.ID, verifier, cfg.Deployment.TokenValidationCache.Std())

	auditLog, err := audit.NewJSONLFileLogger(st.AuditDir(), true)
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("audit log: %w", err)
	}

	renewalRate := newRenewalLimiter(cfg.Limits.RenewalAttemptsPerAccountPerMinute)
	renewal := &sshauth.RenewalConfig{
		Verifier:       verifier,
		Store:          st,
		Rate:           renewalRate,
		Audit:          auditLog,
		MaxAttempts:    cfg.Limits.RenewalAttemptsPerConnection,
		RenewalTimeout: cfg.Listen.RenewalAuthTimeout.Std(),
		DeploymentID:   dep.ID,
		CoderURL:       dep.CoderURL,
		Logger:         logger,
	}
	authCfg := sshauth.AuthConfig{
		TransportUser:        cfg.SSH.TransportUser,
		MaintenanceUser:      cfg.SSH.MaintenanceUser,
		AllowSSHCertificates: cfg.SSH.AllowSSHCertificates,
		DeploymentID:         dep.ID,
		CoderURL:             dep.CoderURL,
		RenewalAuthTimeout:   cfg.Listen.RenewalAuthTimeout.Std(),
		Store:                st,
		Verifier:             cached,
		Audit:                auditLog,
		Logger:               logger,
		Renewal:              renewal,
	}

	codec, err := route.NewCodec(cfg.Deployment.TargetSuffix)
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("target suffix: %w", err)
	}

	registry := tunnel.NewRegistry()
	starter := &tunnel.TunnelStarter{
		Launcher:        &tunnel.Launcher{Dep: dep, Log: logger},
		StartupTimeout:  cfg.Deployment.WorkspaceConnectTimeout.Std(),
		ShutdownGrace:   cfg.Limits.ProcessShutdownGrace.Std(),
		StderrRingBytes: int64(cfg.Limits.StderrBufferBytes),
		Audit:           auditLog,
		Log:             logger,
		Observer:        tunnel.NoopObserver{},
		Rechecker:       &tunnel.Rechecker{Verifier: verifier, Store: st, Log: logger},
		Registry:        registry,
	}

	var maintHandler server.MaintenanceHandler
	if cfg.Maintenance.Enabled {
		maintHandler = &maintenance.Handler{
			Store:    st,
			Renewal:  renewal,
			Verifier: verifier,
			CoderURL: dep.CoderURL.String(),
			Config: maintenance.Config{
				SessionTimeout: cfg.Maintenance.SessionTimeout.Std(),
				InputTimeout:   cfg.Maintenance.InputTimeout.Std(),
				MaxAttempts:    cfg.Limits.RenewalAttemptsPerConnection,
			},
		}
	}

	srv, err := server.New(server.ServerConfig{
		HostSigners:        signers,
		Auth:               authCfg,
		Counters:           limits.New(cfg),
		PreAuthGate:        nil, // T24 wires limits.RateLimits once it exports a constructor
		HandshakeTimeout:   cfg.Listen.HandshakeTimeout.Std(),
		TCPKeepalive:       cfg.Listen.TCPKeepalive.Std(),
		ServerVersion:      cfg.SSH.ServerVersion,
		ProxyProtocol:      cfg.Listen.ProxyProtocol,
		RouteCodec:         codec,
		TunnelStarter:      starter,
		CacheTTL:           cfg.Deployment.TokenValidationCache.Std(),
		MaintenanceHandler: maintHandler,
		Logger:             logger,
		Audit:              auditLog,
	})
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("ssh server: %w", err)
	}

	return &Built{
		Config:     cfg,
		Logger:     logger,
		Store:      st,
		Server:     srv,
		Registry:   registry,
		Deployment: dep,
		Verifier:   verifier,
		auditLog:   auditLog,
	}, nil
}

// Close releases the store flock and audit log. ServeOn must have returned.
func (b *Built) Close() error {
	return b.Store.Close()
}

// ServeOn logs coder CLI/server versions (§31.1-lite) and serves SSH on ln
// until ctx is cancelled or the listener dies. T24 extends this with drain
// grace before close.
func (b *Built) ServeOn(ctx context.Context, ln net.Listener) error {
	tunnel.LogVersions(ctx, b.Logger, b.Deployment)
	return b.Server.Serve(ctx, ln)
}

// cmdServe loads + validates config, assembles the system, and serves until
// the process context (signals) cancels it.
func (c *cli) cmdServe(args []string) int {
	fs := c.newFlagSet("serve")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(c.stderr, "error: serve takes no arguments\n")
		return exitUsage
	}

	path := c.configPath
	if path == "" {
		if c.stateDir == "" {
			fmt.Fprintf(c.stderr, "error: serve requires --state-dir or --config\n")
			return exitUsage
		}
		path = config.DefaultConfigPath(c.stateDir)
	}
	cfg, err := config.Parse(path)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitError
	}
	config.ApplyStateDir(cfg, c.stateDir)
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(c.stderr, "error: invalid config: %v\n", err)
		return exitError
	}

	built, err := Build(cfg, nil)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: startup: %v\n", err)
		return exitError
	}
	defer built.Close()

	ln, err := net.Listen("tcp", cfg.Listen.Address)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: listen %s: %v\n", cfg.Listen.Address, err)
		return exitError
	}
	built.Logger.Info("serving", "address", ln.Addr().String(), "state_dir", cfg.State.Dir)
	if err := built.ServeOn(c.ctx, ln); err != nil {
		fmt.Fprintf(c.stderr, "error: serve: %v\n", err)
		return exitError
	}
	return exitOK
}

// renewalLimiter implements sshauth.RenewalRateLimiter as a per-account
// fixed-window counter plus the §13.6 single-use reconnect allowance.
// TODO(T24): replace with limits.RateLimits once limits exports a
// constructor (its newRateLimits is unexported today).
type renewalLimiter struct {
	mu        sync.Mutex
	maxPerMin int
	windows   map[uuid.UUID]renewalWindow
	allowance map[uuid.UUID]struct{}
}

type renewalWindow struct {
	minute int64
	count  int
}

func newRenewalLimiter(maxPerMin int) *renewalLimiter {
	if maxPerMin <= 0 {
		maxPerMin = 5
	}
	return &renewalLimiter{
		maxPerMin: maxPerMin,
		windows:   make(map[uuid.UUID]renewalWindow),
		allowance: make(map[uuid.UUID]struct{}),
	}
}

func (r *renewalLimiter) AllowRenewalAttempt(accountID uuid.UUID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.allowance[accountID]; ok {
		delete(r.allowance, accountID)
		return true
	}
	now := time.Now().Unix() / 60
	w := r.windows[accountID]
	if w.minute != now {
		w = renewalWindow{minute: now}
	}
	if w.count >= r.maxPerMin {
		r.windows[accountID] = w
		return false
	}
	w.count++
	r.windows[accountID] = w
	return true
}

func (r *renewalLimiter) GrantReconnectAllowance(accountID uuid.UUID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allowance[accountID] = struct{}{}
}
