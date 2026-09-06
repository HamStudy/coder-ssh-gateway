package health

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HamStudy/coder-ssh-gateway/internal/testleaks"
)

func get(t *testing.T, h http.Handler, path string) (int, response) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	h.ServeHTTP(rec, req)
	var r response
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("response not JSON: %v (body %q)", err, rec.Body.String())
	}
	return rec.Code, r
}

func TestLivezAlwaysOK(t *testing.T) {
	defer testleaks.Verify(t)
	s := New(Checks{
		CoderProbe: func(ctx context.Context) error { return errors.New("coder down") },
	}, nil)
	code, r := get(t, s.Handler(), "/livez")
	if code != 200 || r.Status != "alive" {
		t.Errorf("livez = %d %q, want 200 alive (liveness must not depend on Coder, §33.1)", code, r.Status)
	}
}

func TestReadyzAllPass(t *testing.T) {
	defer testleaks.Verify(t)
	s := New(Checks{
		HostKeyLoaded: func(context.Context) error { return nil },
		EncryptionOK:  func(context.Context) error { return nil },
		StoreOK:       func(context.Context) error { return nil },
		ListenerUp:    func() bool { return true },
		SupervisorOK:  func(context.Context) error { return nil },
		CoderProbe:    func(context.Context) error { return nil },
	}, nil)
	code, r := get(t, s.Handler(), "/readyz")
	if code != 200 || r.Status != "ready" {
		t.Errorf("readyz = %d %q, want 200 ready", code, r.Status)
	}
	if !r.CoderReachable || r.Degraded {
		t.Errorf("coder_reachable=%v degraded=%v, want true/false", r.CoderReachable, r.Degraded)
	}
	for _, name := range []string{"host_key", "encryption", "store", "listener", "supervisor"} {
		if r.Checks[name] != "ok" && r.Checks[name] != "up" {
			t.Errorf("check %s = %q", name, r.Checks[name])
		}
	}
}

func TestReadyzCoderOutageIsDegradedNotFailed(t *testing.T) {
	defer testleaks.Verify(t)
	s := New(Checks{
		HostKeyLoaded: func(context.Context) error { return nil },
		EncryptionOK:  func(context.Context) error { return nil },
		StoreOK:       func(context.Context) error { return nil },
		ListenerUp:    func() bool { return true },
		SupervisorOK:  func(context.Context) error { return nil },
		CoderProbe:    func(context.Context) error { return errors.New("connection refused") },
	}, nil)
	code, r := get(t, s.Handler(), "/readyz")
	if code != 200 {
		t.Errorf("readyz during Coder outage = %d, want 200 (degraded, not a gate, §33.2)", code)
	}
	if r.CoderReachable || !r.Degraded {
		t.Errorf("coder_reachable=%v degraded=%v, want false/true", r.CoderReachable, r.Degraded)
	}
	if r.Status != "ready" {
		t.Errorf("status = %q, want ready", r.Status)
	}
}

func TestReadyzHardCheckFails(t *testing.T) {
	defer testleaks.Verify(t)
	s := New(Checks{
		HostKeyLoaded: func(context.Context) error { return nil },
		EncryptionOK:  func(context.Context) error { return errors.New("no active key") },
		StoreOK:       func(context.Context) error { return nil },
		ListenerUp:    func() bool { return true },
		SupervisorOK:  func(context.Context) error { return nil },
		CoderProbe:    func(context.Context) error { return nil },
	}, nil)
	code, r := get(t, s.Handler(), "/readyz")
	if code != 503 || r.Status != "not_ready" {
		t.Errorf("readyz = %d %q, want 503 not_ready", code, r.Status)
	}
	if r.Checks["encryption"] != "failed" {
		t.Errorf("checks.encryption = %q, want failed", r.Checks["encryption"])
	}
	if r.Checks["host_key"] != "ok" {
		t.Errorf("checks.host_key = %q, want ok", r.Checks["host_key"])
	}
}

func TestReadyzDrainingIsNotReady(t *testing.T) {
	defer testleaks.Verify(t)
	draining := atomic.Bool{}
	s := New(Checks{
		ListenerUp: func() bool { return true },
		CoderProbe: func(context.Context) error { return nil },
		Draining:   draining.Load,
	}, nil)

	code, _ := get(t, s.Handler(), "/readyz")
	if code != 200 {
		t.Fatalf("readyz before drain = %d, want 200", code)
	}
	draining.Store(true)
	code, r := get(t, s.Handler(), "/readyz")
	if code != 503 || r.Checks["draining"] != "true" {
		t.Errorf("readyz during drain = %d draining=%q, want 503 true (§32 step 2)", code, r.Checks["draining"])
	}
}

func TestCoderProbeCached(t *testing.T) {
	defer testleaks.Verify(t)
	var calls atomic.Int32
	s := New(Checks{
		ListenerUp:    func() bool { return true },
		CoderProbe:    func(context.Context) error { calls.Add(1); return errors.New("down") },
		ProbeCacheTTL: time.Minute,
	}, nil)
	for i := 0; i < 5; i++ {
		get(t, s.Handler(), "/readyz")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("coder probe ran %d times in 5 scrapes, want 1 (cache TTL)", got)
	}
}

func TestNoPprofRegistered(t *testing.T) {
	defer testleaks.Verify(t)
	s := New(Checks{}, nil)
	for _, path := range []string{"/debug/pprof/", "/debug/pprof/heap", "/metrics"} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != 404 {
			t.Errorf("%s = %d, want 404 (§33.3)", path, rec.Code)
		}
	}
}

func TestServeShutdown(t *testing.T) {
	defer testleaks.Verify(t)
	s := New(Checks{}, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- s.Serve(ctx, ln) }()

	resp, err := http.Get("http://" + ln.Addr().String() + "/livez")
	if err != nil {
		t.Fatalf("GET livez: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("livez = %d, want 200", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Serve returned %v, want nil on clean shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Serve did not return after ctx cancel")
	}
}
