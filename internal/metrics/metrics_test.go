package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/taxilian/coder-ssh-gateway/internal/config"
	"github.com/taxilian/coder-ssh-gateway/internal/limits"
)

// requiredFamilies are the §34.2 metric names, byte-exact.
var requiredFamilies = []string{
	"coder_ssh_gateway_connections_active",
	"coder_ssh_gateway_connections_total",
	"coder_ssh_gateway_auth_attempts_total",
	"coder_ssh_gateway_auth_duration_seconds",
	"coder_ssh_gateway_credential_validations_total",
	"coder_ssh_gateway_credential_validation_duration_seconds",
	"coder_ssh_gateway_credential_renewals_total",
	"coder_ssh_gateway_channels_active",
	"coder_ssh_gateway_channels_total",
	"coder_ssh_gateway_coder_processes_active",
	"coder_ssh_gateway_coder_process_exits_total",
	"coder_ssh_gateway_tunnel_bytes_total",
	"coder_ssh_gateway_limit_rejections_total",
	"coder_ssh_gateway_store_operations_total",
}

func gatherText(t *testing.T, m *Metrics) string {
	t.Helper()
	mfs, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var sb strings.Builder
	for _, mf := range mfs {
		sb.WriteString(mf.GetName())
		sb.WriteString("\n")
	}
	return sb.String()
}

func TestAllRequiredFamiliesPresent(t *testing.T) {
	m := New()
	got := gatherText(t, m)
	for _, fam := range requiredFamilies {
		if !strings.Contains(got, fam+"\n") {
			t.Errorf("missing metric family %s", fam)
		}
	}
}

func TestNoHighCardinalityLabels(t *testing.T) {
	m := New()
	mfs, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	allowed := map[string]bool{
		"result": true, "method": true, "class": true, "direction": true,
		"limit": true, "operation": true,
	}
	for _, mf := range mfs {
		if !strings.HasPrefix(mf.GetName(), "coder_ssh_gateway_") {
			continue // go/process collectors
		}
		for _, metric := range mf.GetMetric() {
			for _, lp := range metric.GetLabel() {
				if !allowed[lp.GetName()] {
					t.Errorf("family %s has disallowed label %q", mf.GetName(), lp.GetName())
				}
			}
		}
	}
}

func TestRecorderCounts(t *testing.T) {
	m := New()

	m.ConnectionOpened()
	m.ConnectionOpened()
	m.ConnectionClosed(ResultSuccess)
	m.ConnectionClosed(ResultFailure)

	expected := `
# HELP coder_ssh_gateway_connections_active Currently open outer SSH connections (any auth state).
# TYPE coder_ssh_gateway_connections_active gauge
coder_ssh_gateway_connections_active 0
# HELP coder_ssh_gateway_connections_total Outer SSH connections by terminal result.
# TYPE coder_ssh_gateway_connections_total counter
coder_ssh_gateway_connections_total{result="failure"} 1
coder_ssh_gateway_connections_total{result="rejected"} 0
coder_ssh_gateway_connections_total{result="success"} 1
`
	if err := testutil.GatherAndCompare(m.Registry, strings.NewReader(expected),
		"coder_ssh_gateway_connections_active", "coder_ssh_gateway_connections_total"); err != nil {
		t.Error(err)
	}

	m.AuthAttempt("publickey", ResultSuccess)
	m.AuthAttempt("publickey", ResultFailure)
	m.AuthAttempt("keyboard-interactive", ResultFailure)
	m.AuthAttempt("git-shell", ResultFailure) // unbounded client input -> "other"

	expected = `
# HELP coder_ssh_gateway_auth_attempts_total SSH auth attempts by method and result.
# TYPE coder_ssh_gateway_auth_attempts_total counter
coder_ssh_gateway_auth_attempts_total{method="keyboard_interactive",result="failure"} 1
coder_ssh_gateway_auth_attempts_total{method="keyboard_interactive",result="success"} 0
coder_ssh_gateway_auth_attempts_total{method="none",result="failure"} 0
coder_ssh_gateway_auth_attempts_total{method="none",result="success"} 0
coder_ssh_gateway_auth_attempts_total{method="other",result="failure"} 1
coder_ssh_gateway_auth_attempts_total{method="other",result="success"} 0
coder_ssh_gateway_auth_attempts_total{method="password",result="failure"} 0
coder_ssh_gateway_auth_attempts_total{method="password",result="success"} 0
coder_ssh_gateway_auth_attempts_total{method="publickey",result="failure"} 1
coder_ssh_gateway_auth_attempts_total{method="publickey",result="success"} 1
`
	if err := testutil.GatherAndCompare(m.Registry, strings.NewReader(expected),
		"coder_ssh_gateway_auth_attempts_total"); err != nil {
		t.Error(err)
	}
}

func TestChannelAndLimitCounts(t *testing.T) {
	m := New()
	m.ChannelAccepted()
	m.ChannelAccepted()
	m.ChannelClosed()
	m.ChannelRejected()
	m.LimitRejection(string(limits.ReasonKeyConn))
	m.LimitRejection("totally-unbounded-input")

	expected := `
# HELP coder_ssh_gateway_channels_active Currently open SSH channels.
# TYPE coder_ssh_gateway_channels_active gauge
coder_ssh_gateway_channels_active 1
# HELP coder_ssh_gateway_channels_total SSH channel open requests by result.
# TYPE coder_ssh_gateway_channels_total counter
coder_ssh_gateway_channels_total{result="accepted"} 2
coder_ssh_gateway_channels_total{result="rejected"} 1
`
	if err := testutil.GatherAndCompare(m.Registry, strings.NewReader(expected),
		"coder_ssh_gateway_channels_active", "coder_ssh_gateway_channels_total"); err != nil {
		t.Error(err)
	}

	limitExpected := `
# HELP coder_ssh_gateway_limit_rejections_total Admissions rejected by a resource limit, by limit name.
# TYPE coder_ssh_gateway_limit_rejections_total counter
coder_ssh_gateway_limit_rejections_total{limit="account_conn"} 0
coder_ssh_gateway_limit_rejections_total{limit="channel_account"} 0
coder_ssh_gateway_limit_rejections_total{limit="channel_conn"} 0
coder_ssh_gateway_limit_rejections_total{limit="coder_api"} 0
coder_ssh_gateway_limit_rejections_total{limit="coder_process"} 0
coder_ssh_gateway_limit_rejections_total{limit="global_conn"} 0
coder_ssh_gateway_limit_rejections_total{limit="handshake"} 0
coder_ssh_gateway_limit_rejections_total{limit="ip_conn"} 0
coder_ssh_gateway_limit_rejections_total{limit="key_conn"} 1
coder_ssh_gateway_limit_rejections_total{limit="other"} 1
coder_ssh_gateway_limit_rejections_total{limit="pre_auth_ip"} 0
coder_ssh_gateway_limit_rejections_total{limit="renewal_rate"} 0
coder_ssh_gateway_limit_rejections_total{limit="unknown_key_attempt"} 0
`
	if err := testutil.GatherAndCompare(m.Registry, strings.NewReader(limitExpected),
		"coder_ssh_gateway_limit_rejections_total"); err != nil {
		t.Error(err)
	}
}

func TestTunnelObserver(t *testing.T) {
	m := New()
	m.ProcessStarted()
	m.ProcessStarted()
	m.ProcessExited("") // clean exit -> class "ok"
	m.ActiveGauge(0)    // must NOT clobber the still-active process
	m.TunnelBytes(DirUp, 100)
	m.TunnelBytes(DirDown, 250)
	m.TunnelBytes("sideways", 999) // ignored

	expected := `
# HELP coder_ssh_gateway_coder_processes_active Currently running coder child processes.
# TYPE coder_ssh_gateway_coder_processes_active gauge
coder_ssh_gateway_coder_processes_active 1
`
	if err := testutil.GatherAndCompare(m.Registry, strings.NewReader(expected),
		"coder_ssh_gateway_coder_processes_active"); err != nil {
		t.Error(err)
	}

	bytesExpected := `
# HELP coder_ssh_gateway_tunnel_bytes_total Bytes proxied between client channels and coder processes by direction.
# TYPE coder_ssh_gateway_tunnel_bytes_total counter
coder_ssh_gateway_tunnel_bytes_total{direction="down"} 250
coder_ssh_gateway_tunnel_bytes_total{direction="up"} 100
`
	if err := testutil.GatherAndCompare(m.Registry, strings.NewReader(bytesExpected),
		"coder_ssh_gateway_tunnel_bytes_total"); err != nil {
		t.Error(err)
	}

	exitsExpected := `
# HELP coder_ssh_gateway_coder_process_exits_total Coder child process exits by supervision class.
# TYPE coder_ssh_gateway_coder_process_exits_total counter
coder_ssh_gateway_coder_process_exits_total{class="TUNNEL_CANCELLED"} 0
coder_ssh_gateway_coder_process_exits_total{class="TUNNEL_CODER_EXITED"} 0
coder_ssh_gateway_coder_process_exits_total{class="TUNNEL_START_TIMEOUT"} 0
coder_ssh_gateway_coder_process_exits_total{class="TUNNEL_STREAM_FAILED"} 0
coder_ssh_gateway_coder_process_exits_total{class="ok"} 1
`
	if err := testutil.GatherAndCompare(m.Registry, strings.NewReader(exitsExpected),
		"coder_ssh_gateway_coder_process_exits_total"); err != nil {
		t.Error(err)
	}
}

func TestCredentialValidationAndStoreOps(t *testing.T) {
	m := New()
	m.CredentialValidation(ValidationInvalid, 25*time.Millisecond)
	m.CredentialValidation(ResultSuccess, 10*time.Millisecond)
	m.CredentialValidation("garbage", time.Millisecond) // -> "error"
	m.StoreOperation(StoreOpLoadCredential, ResultSuccess)
	m.StoreOperation(StoreOpLookupKey, ResultFailure)
	m.CredentialRenewal(MethodToken, ResultSuccess)
	m.CredentialRenewal("keyboard-interactive", ResultFailure) // normalized to token

	checks := []struct {
		name string
		got  float64
		want float64
	}{
		{"validations invalid", testutil.ToFloat64(m.credValidations.WithLabelValues("invalid")), 1},
		{"validations success", testutil.ToFloat64(m.credValidations.WithLabelValues("success")), 1},
		{"validations error", testutil.ToFloat64(m.credValidations.WithLabelValues("error")), 1},
		{"store load ok", testutil.ToFloat64(m.storeOps.WithLabelValues("load_credential", "success")), 1},
		{"store lookup fail", testutil.ToFloat64(m.storeOps.WithLabelValues("lookup_key", "failure")), 1},
		{"renewal success", testutil.ToFloat64(m.credRenewals.WithLabelValues("token", "success")), 1},
		{"renewal failure", testutil.ToFloat64(m.credRenewals.WithLabelValues("token", "failure")), 1},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}

	count := testutil.CollectAndCount(m.credValidationDur)
	if count != 9 { // every pre-created result series
		t.Errorf("credential_validation_duration_seconds series count = %d, want 9", count)
	}
}

func TestPollLimitsUsage(t *testing.T) {
	m := New()
	cfg := config.Default()
	c := limits.New(cfg)

	rel, ok := c.AcquireGlobal()
	if !ok {
		t.Fatal("AcquireGlobal failed")
	}
	defer rel()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.PollLimitsUsage(ctx, c, map[string]int{
			string(limits.ReasonGlobalConn): cfg.Limits.UnauthenticatedConnections,
		}, 10*time.Millisecond)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		v := testutil.ToFloat64(m.limitsUsage.WithLabelValues(string(limits.ReasonGlobalConn)))
		if v == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("limits_usage gauge never reached 1, last=%v", v)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := testutil.ToFloat64(m.limitsMax.WithLabelValues(string(limits.ReasonGlobalConn))); got != 128 {
		t.Errorf("limits_max = %v, want 128", got)
	}
	cancel()
	<-done
}

func TestHandlerServesMetricsOnly(t *testing.T) {
	m := New()
	h := m.Handler()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("/metrics status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "coder_ssh_gateway_connections_active") {
		t.Error("/metrics body missing required family")
	}

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	h.ServeHTTP(rec2, req2)
	if rec2.Code != 404 {
		t.Errorf("/debug/pprof/ status = %d, want 404 (no pprof on this mux, §33.3)", rec2.Code)
	}
}
