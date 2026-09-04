// Package health implements the §33 health endpoints: /livez reports only
// process liveness (never Coder reachability, §33.1), and /readyz runs the
// §33.2 readiness checks (host key, encryption provider, state store,
// listener, supervisor) with Coder reachability exposed as a non-gating
// detail/degraded field.
//
// The handler is a dedicated ServeMux with exactly two routes; no pprof or
// other diagnostic endpoints are ever registered here (§33.3).
package health

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/taxilian/coder-ssh-gateway/internal/version"
)

// Checks supplies the readiness probes. Nil hard checks are treated as
// passing (partial assemblies in tests); a nil CoderProbe reports
// coder_reachable=false without degrading readiness.
type Checks struct {
	// HostKeyLoaded verifies the outer SSH host key is available (§33.2).
	HostKeyLoaded func(ctx context.Context) error
	// EncryptionOK verifies the credential encryption provider (§33.2).
	EncryptionOK func(ctx context.Context) error
	// StoreOK verifies the state store is open, the lock held, and VERSION
	// current (§33.2 database-reachable adaptation for the flat-file store).
	StoreOK func(ctx context.Context) error
	// ListenerUp reports whether the SSH listener is initialized (§33.2).
	ListenerUp func() bool
	// SupervisorOK verifies the child-process supervisor preconditions
	// (e.g. the configured coder binary exists and is executable).
	SupervisorOK func(ctx context.Context) error
	// Draining reports graceful-shutdown drain state (§32 step 2): when
	// true, /readyz answers 503 so load balancers stop sending traffic.
	Draining func() bool
	// CoderProbe checks control-plane reachability. Detail only (§33.2):
	// failure sets coder_reachable=false + degraded=true but never fails
	// readiness.
	CoderProbe func(ctx context.Context) error
	// ProbeCacheTTL bounds how often CoderProbe actually runs (default 10s)
	// so scrape frequency never translates into control-plane load.
	ProbeCacheTTL time.Duration
	// CheckTimeout bounds each individual readiness probe (default 2s).
	CheckTimeout time.Duration
}

type response struct {
	Status         string            `json:"status"`
	Version        string            `json:"version"`
	Checks         map[string]string `json:"checks,omitempty"`
	CoderReachable bool              `json:"coder_reachable"`
	Degraded       bool              `json:"degraded"`
}

// Server serves the health endpoints.
type Server struct {
	checks Checks
	log    *slog.Logger

	probeMu     sync.Mutex
	probeAt     time.Time
	probeResult error
	probeRan    bool
}

// New builds the health server; log may be nil.
func New(checks Checks, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	if checks.ProbeCacheTTL <= 0 {
		checks.ProbeCacheTTL = 10 * time.Second
	}
	if checks.CheckTimeout <= 0 {
		checks.CheckTimeout = 2 * time.Second
	}
	return &Server{checks: checks, log: log}
}

// Handler returns the dedicated two-route mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", s.handleLivez)
	mux.HandleFunc("/readyz", s.handleReadyz)
	return mux
}

// handleLivez implements §33.1: process liveness only. It never consults
// Coder, the store, or any external dependency, so a control-plane outage
// can never cascade into a restart storm.
func (s *Server) handleLivez(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, response{Status: "alive", Version: version.Version})
}

// handleReadyz implements §33.2: all hard checks must pass and the server
// must not be draining. Coder reachability is reported as a detail.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	checks := map[string]string{}
	ready := true

	run := func(name string, fn func(ctx context.Context) error) {
		if fn == nil {
			checks[name] = "ok"
			return
		}
		cctx, cancel := context.WithTimeout(ctx, s.checks.CheckTimeout)
		defer cancel()
		if err := fn(cctx); err != nil {
			checks[name] = "failed"
			ready = false
			s.log.Debug("readiness check failed", slog.String("check", name), slog.String("detail", err.Error()))
			return
		}
		checks[name] = "ok"
	}

	run("host_key", s.checks.HostKeyLoaded)
	run("encryption", s.checks.EncryptionOK)
	run("store", s.checks.StoreOK)
	run("supervisor", s.checks.SupervisorOK)

	if s.checks.ListenerUp != nil && !s.checks.ListenerUp() {
		checks["listener"] = "down"
		ready = false
	} else {
		checks["listener"] = "up"
	}

	if s.checks.Draining != nil && s.checks.Draining() {
		checks["draining"] = "true"
		ready = false
	}

	coderReachable := s.cachedCoderProbe(ctx)

	status := "ready"
	code := http.StatusOK
	if !ready {
		status = "not_ready"
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, response{
		Status:         status,
		Version:        version.Version,
		Checks:         checks,
		CoderReachable: coderReachable,
		Degraded:       !coderReachable,
	})
}

// cachedCoderProbe runs the Coder probe at most once per ProbeCacheTTL.
func (s *Server) cachedCoderProbe(ctx context.Context) bool {
	s.probeMu.Lock()
	if s.probeRan && time.Since(s.probeAt) < s.checks.ProbeCacheTTL {
		err := s.probeResult
		s.probeMu.Unlock()
		return err == nil
	}
	s.probeMu.Unlock()

	var err error
	if s.checks.CoderProbe != nil {
		cctx, cancel := context.WithTimeout(ctx, s.checks.CheckTimeout)
		err = s.checks.CoderProbe(cctx)
		cancel()
	} else {
		err = errors.New("no coder probe configured")
	}

	s.probeMu.Lock()
	s.probeAt = time.Now()
	s.probeResult = err
	s.probeRan = true
	s.probeMu.Unlock()
	return err == nil
}

func writeJSON(w http.ResponseWriter, code int, v response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// Serve runs the health HTTP server on ln until ctx is cancelled, then
// shuts it down gracefully (bounded 2s). Returns nil on clean shutdown.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	httpSrv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- httpSrv.Serve(ln)
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		<-errCh
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
