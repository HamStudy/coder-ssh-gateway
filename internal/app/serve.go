package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HamStudy/coder-ssh-gateway/internal/audit"
	"github.com/HamStudy/coder-ssh-gateway/internal/coderapi"
	"github.com/HamStudy/coder-ssh-gateway/internal/config"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/health"
	"github.com/HamStudy/coder-ssh-gateway/internal/limits"
	"github.com/HamStudy/coder-ssh-gateway/internal/metrics"
	"github.com/HamStudy/coder-ssh-gateway/internal/route"
	"github.com/HamStudy/coder-ssh-gateway/internal/server"
	"github.com/HamStudy/coder-ssh-gateway/internal/sshauth"
	"github.com/HamStudy/coder-ssh-gateway/internal/store"
	"github.com/HamStudy/coder-ssh-gateway/internal/tunnel"
)

// Built is the fully assembled gateway: metrics, limits, instrumented
// wrappers, and the health surface attach here (T24).
type Built struct {
	Config     *config.Config
	Logger     *slog.Logger
	Store      *store.Store
	Server     *server.Server
	Registry   *tunnel.Registry
	Deployment core.Deployment
	Verifier   *coderapi.Verifier
	Metrics    *metrics.Metrics
	Counters   *limits.Counters

	auditLog *audit.JSONLFileLogger
	keyProv  interface {
		ActiveKey(ctx context.Context) (string, []byte, error)
	}
	serving atomic.Bool
	auxWg   sync.WaitGroup
}

// Build assembles the running system from a validated config: host keys,
// store + encryption, metrics, verifier (instrumented with the §20 API
// semaphore + §34.2 metrics), auth callbacks, renewal, tunnel starter,
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
	kp := KeyProviderFromConfig(cfg, logger)
	st.SetKeyProvider(kp)
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

	m := metrics.New()
	counters := limits.New(cfg)

	// Instrumented wrappers (§20/§34.2): the verifier wrapper carries the
	// global Coder-API semaphore and validation metrics; it sits inside the
	// cached verifier so cache hits never hit the semaphore.
	instVerifier := &instrumentedVerifier{inner: verifier, counters: counters, rec: m}
	cached := coderapi.NewCachedVerifier(dep.ID, instVerifier, cfg.Deployment.TokenValidationCache.Std())
	instStore := &instrumentedStore{Store: st, rec: m}

	auditLog, err := audit.NewJSONLFileLogger(st.AuditDir(), true)
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("audit log: %w", err)
	}
	auditOut := &auditMetricBridge{inner: auditLog, rec: m}

	rateLimits := limits.NewRateLimits(cfg.Limits)
	renewal := &sshauth.RenewalConfig{
		Verifier:       instVerifier,
		Store:          instStore,
		Rate:           rateLimits,
		Audit:          auditOut,
		MaxAttempts:    cfg.Limits.RenewalAttemptsPerConnection,
		RenewalTimeout: cfg.Listen.RenewalAuthTimeout.Std(),
		DeploymentID:   dep.ID,
		CoderURL:       dep.CoderURL,
		Logger:         logger,
	}

	// CD-2: enrollment disabled leaves a nil Enrollment — login@ then
	// rejects byte-identically to any unknown username (§35).
	var enrollment *sshauth.EnrollmentConfig
	if cfg.Enrollment.Enabled {
		enrollment = &sshauth.EnrollmentConfig{
			Enabled:  true,
			User:     cfg.Enrollment.User,
			Verifier: instVerifier,
			// Raw verifier: the hint is best-effort and must not contend
			// for the auth semaphore or pollute validation metrics.
			Workspaces: verifier,
			Store:      instStore,
			Rate:       rateLimits,
			// §20: bound pre-resolution token guessing per source IP with
			// the unknown-key attempt bucket.
			PreTokenGate:   rateLimits.AllowUnknownKeyAttempt,
			Audit:          auditOut,
			MaxAttempts:    cfg.Enrollment.MaxAttempts,
			RenewalTimeout: cfg.Enrollment.Timeout.Std(),
			DeploymentID:   dep.ID,
			CoderURL:       dep.CoderURL,
			Logger:         logger,
		}
	}
	authCfg := sshauth.AuthConfig{
		DeploymentID:       dep.ID,
		CoderURL:           dep.CoderURL,
		RenewalAuthTimeout: cfg.Listen.RenewalAuthTimeout.Std(),
		Store:              instStore,
		Verifier:           cached,
		Audit:              auditOut,
		Logger:             logger,
		Renewal:            renewal,
		EnrollmentUser:     cfg.Enrollment.User,
		Enrollment:         enrollment,
	}

	codec := route.NewCodec()

	registry := tunnel.NewRegistry()
	starter := &tunnel.TunnelStarter{
		Launcher:        &tunnel.Launcher{Dep: dep, Log: logger},
		StartupTimeout:  cfg.Deployment.WorkspaceConnectTimeout.Std(),
		ShutdownGrace:   cfg.Limits.ProcessShutdownGrace.Std(),
		StderrRingBytes: int64(cfg.Limits.StderrBufferBytes),
		Audit:           auditOut,
		Log:             logger,
		Observer:        m,
		Rechecker:       &tunnel.Rechecker{Verifier: instVerifier, Store: instStore, Log: logger},
		Registry:        registry,
	}
	workspaceTransports := &tunnel.TransportFactory{
		Launcher:        &tunnel.Launcher{Dep: dep, Log: logger},
		StartupTimeout:  cfg.Deployment.WorkspaceConnectTimeout.Std(),
		ShutdownGrace:   cfg.Limits.ProcessShutdownGrace.Std(),
		StderrRingBytes: int64(cfg.Limits.StderrBufferBytes),
		Log:             logger,
		Rechecker:       &tunnel.Rechecker{Verifier: instVerifier, Store: instStore, Log: logger},
		Registry:        registry,
	}

	srv, err := server.New(server.ServerConfig{
		HostSigners:         signers,
		Auth:                authCfg,
		Counters:            counters,
		PreAuthGate:         rateLimits.AllowPreAuthIP,
		HandshakeTimeout:    cfg.Listen.HandshakeTimeout.Std(),
		TCPKeepalive:        cfg.Listen.TCPKeepalive.Std(),
		ServerVersion:       cfg.SSH.ServerVersion,
		ProxyProtocol:       cfg.Listen.ProxyProtocol,
		RouteCodec:          codec,
		TunnelStarter:       starter,
		WorkspaceTransports: workspaceTransports,
		CacheTTL:            cfg.Deployment.TokenValidationCache.Std(),
		Metrics:             m,
		// §32 step 4: the drain period reuses limits.process_shutdown_grace
		// (documented choice): the same budget governs graceful channel
		// finish and child-process TERM/KILL escalation.
		DrainPeriod: cfg.Limits.ProcessShutdownGrace.Std(),
		Logger:      logger,
		Audit:       auditOut,
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
		Metrics:    m,
		Counters:   counters,
		auditLog:   auditLog,
		keyProv:    kp,
	}, nil
}

// Close flushes and closes the audit log, then releases the store flock —
// the §32 steps 7-8 order (audit before store).
func (b *Built) Close() error {
	var errs []error
	if b.auditLog != nil {
		if err := b.auditLog.Close(); err != nil {
			errs = append(errs, fmt.Errorf("audit log close: %w", err))
		}
	}
	if err := b.Store.Close(); err != nil {
		errs = append(errs, fmt.Errorf("store close: %w", err))
	}
	return errors.Join(errs...)
}

// HealthChecks builds the §33 readiness probes over the assembled system.
func (b *Built) HealthChecks() health.Checks {
	cfg := b.Config
	return health.Checks{
		HostKeyLoaded: func(context.Context) error {
			_, _, err := server.LoadHostSigners(cfg.SSH.HostKeys)
			return err
		},
		EncryptionOK: func(ctx context.Context) error {
			_, _, err := b.keyProv.ActiveKey(ctx)
			return err
		},
		StoreOK: func(context.Context) error {
			raw, err := os.ReadFile(filepath.Join(cfg.State.Dir, "VERSION"))
			if err != nil {
				return err
			}
			if v := strings.TrimSpace(string(raw)); v != "1" {
				return fmt.Errorf("store VERSION %q unsupported", v)
			}
			return nil
		},
		ListenerUp: b.serving.Load,
		SupervisorOK: func(context.Context) error {
			info, err := os.Stat(b.Deployment.CoderBinary)
			if err != nil {
				return err
			}
			if info.IsDir() || info.Mode().Perm()&0o111 == 0 {
				return fmt.Errorf("coder binary %s is not executable", b.Deployment.CoderBinary)
			}
			return nil
		},
		Draining:   b.Server.Draining,
		CoderProbe: b.coderProbe(),
	}
}

// coderProbe returns a reachability check against /api/v2/buildinfo using
// the deployment's hardened HTTP client (custom CA / mTLS honored). It is a
// readiness DETAIL only (§33.2) — callers must not gate readiness on it.
func (b *Built) coderProbe() func(ctx context.Context) error {
	vopts, err := VerifierOptionsFromConfig(b.Config)
	if err != nil {
		return func(context.Context) error { return err }
	}
	client, err := coderapi.NewHTTPClient(vopts)
	if err != nil {
		return func(context.Context) error { return err }
	}
	u := b.Deployment.CoderURL
	if u == nil {
		return func(context.Context) error { return errors.New("no coder_url configured") }
	}
	probeURL := u.JoinPath("/api/v2/buildinfo").String()
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("buildinfo returned HTTP %d", resp.StatusCode)
		}
		return nil
	}
}

// ServeOn starts the auxiliary servers (metrics, health), the limits-usage
// poller, and the audit retention job, then serves SSH on ln until ctx is
// cancelled. On return the SSH server has drained (§32) and all auxiliary
// goroutines have exited; the caller should then Close the Built.
func (b *Built) ServeOn(ctx context.Context, ln net.Listener) error {
	tunnel.LogVersions(ctx, b.Logger, b.Deployment)

	metricsLn, err := listenOptional(b.Config.Observability.MetricsAddress)
	if err != nil {
		return fmt.Errorf("metrics listener: %w", err)
	}
	healthLn, err := listenOptional(b.Config.Observability.HealthAddress)
	if err != nil {
		if metricsLn != nil {
			metricsLn.Close()
		}
		return fmt.Errorf("health listener: %w", err)
	}

	healthSrv := health.New(b.HealthChecks(), b.Logger)
	b.serving.Store(true)
	defer b.serving.Store(false)

	if metricsLn != nil {
		b.auxWg.Add(1)
		go func() {
			defer b.auxWg.Done()
			serveHTTPOn(ctx, metricsLn, b.Metrics.Handler(), b.Logger, "metrics")
		}()
		b.Logger.Info("metrics endpoint listening", slog.String("address", metricsLn.Addr().String()))
	}
	if healthLn != nil {
		b.auxWg.Add(1)
		go func() {
			defer b.auxWg.Done()
			if err := healthSrv.Serve(ctx, healthLn); err != nil {
				b.Logger.Error("health server failed", slog.String("detail", err.Error()))
			}
		}()
		b.Logger.Info("health endpoint listening", slog.String("address", healthLn.Addr().String()))
	}

	b.auxWg.Add(1)
	go func() {
		defer b.auxWg.Done()
		b.Metrics.PollLimitsUsage(ctx, b.Counters, limitsMaxima(b.Config), 5*time.Second)
	}()

	b.auxWg.Add(1)
	go func() {
		defer b.auxWg.Done()
		runAuditRetention(ctx, b.Store.AuditDir(), b.Config.State.AuditRetentionDays, time.Hour, nil, b.Logger)
	}()

	serveErr := b.Server.Serve(ctx, ln)
	b.auxWg.Wait()
	return serveErr
}

// listenOptional binds addr; an empty address disables the listener.
func listenOptional(addr string) (net.Listener, error) {
	if addr == "" {
		return nil, nil
	}
	return net.Listen("tcp", addr)
}

// serveHTTPOn serves handler on ln until ctx cancels, then shuts down.
func serveHTTPOn(ctx context.Context, ln net.Listener, handler http.Handler, log *slog.Logger, name string) {
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		<-errCh
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error(name+" server failed", slog.String("detail", err.Error()))
		}
	}
}

// limitsMaxima maps the §20 config limits for the limits_max gauge.
func limitsMaxima(cfg *config.Config) map[string]int {
	return map[string]int{
		string(limits.ReasonGlobalConn):     cfg.Limits.UnauthenticatedConnections,
		string(limits.ReasonHandshake):      cfg.Limits.Handshakes,
		string(limits.ReasonIPConn):         cfg.Limits.ConnectionsPerIP,
		string(limits.ReasonKeyConn):        cfg.Limits.ConnectionsPerKey,
		string(limits.ReasonAccountConn):    cfg.Limits.ConnectionsPerAccount,
		string(limits.ReasonChannelConn):    cfg.Limits.ChannelsPerConnection,
		string(limits.ReasonChannelAccount): cfg.Limits.ChannelsPerAccount,
		string(limits.ReasonCoderProcess):   cfg.Limits.CoderProcesses,
		string(limits.ReasonCoderAPI):       cfg.Limits.CoderAPIRequests,
		string(limits.ReasonRenewalRate):    cfg.Limits.RenewalAttemptsPerAccountPerMinute,
	}
}

type bindAddressOverride struct {
	field string
	value string
}

func (c *cli) applyBindAddressOverrides(cfg *config.Config) []bindAddressOverride {
	overrides := []struct {
		flag  explicitString
		field string
		dest  *string
	}{
		{c.listenAddress, "listen.address", &cfg.Listen.Address},
		{c.metricsAddress, "observability.metrics_address", &cfg.Observability.MetricsAddress},
		{c.healthAddress, "observability.health_address", &cfg.Observability.HealthAddress},
	}
	applied := make([]bindAddressOverride, 0, len(overrides))
	for _, override := range overrides {
		if !override.flag.set {
			continue
		}
		*override.dest = override.flag.value
		applied = append(applied, bindAddressOverride{field: override.field, value: override.flag.value})
	}
	return applied
}

func logBindAddressOverrides(logger *slog.Logger, overrides []bindAddressOverride) {
	for _, override := range overrides {
		logger.Info("config CLI override applied",
			"field", override.field,
			"source", "flag",
			"value", override.value,
		)
	}
}

// cmdServe loads + validates config, assembles the system, and serves until
// the process context (SIGINT/SIGTERM via signal.NotifyContext in main)
// cancels it; the §32 drain runs inside ServeOn.
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
	envApplied, err := config.ApplyEnvOverrides(cfg)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: %v\n", err)
		return exitError
	}
	flagApplied := c.applyBindAddressOverrides(cfg)
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
	if len(envApplied) > 0 {
		built.Logger.Info("config environment overrides applied", "vars", envApplied)
	}
	logBindAddressOverrides(built.Logger, flagApplied)

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
	built.Logger.Info("shutdown complete")
	return exitOK
}
