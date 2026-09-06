// Package metrics implements the §34.2 Prometheus surface: one registry
// with the exact coder_ssh_gateway_* metric families, bounded label values
// only (never user, key, workspace, or target names), the tunnel.Observer
// implementation for coder-process lifecycle and byte counters, and the
// Recorder interface consumed by the SSH server and app-level instrumenting
// wrappers.
//
// Everything is nil-safe through NoopRecorder so tests and partial
// assemblies can opt out without nil checks at every call site.
package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/HamStudy/coder-ssh-gateway/internal/limits"
)

// namespace is the §34.2 metric prefix; combined with each Name below it
// produces the exact required metric names.
const namespace = "coder_ssh_gateway"

// Bounded label values. Anything outside these sets is normalized to a
// catch-all so client input can never create label cardinality (§34.2).
const (
	ResultSuccess   = "success"
	ResultFailure   = "failure"
	ResultRejected  = "rejected"
	ResultWrongUser = "wrong_user"

	DirUp   = "up"
	DirDown = "down"

	MethodPublicKey           = "publickey"
	MethodPassword            = "password"
	MethodKeyboardInteractive = "keyboard_interactive"
	MethodNone                = "none"
	MethodOther               = "other"

	// MethodToken labels credential renewals: every renewal path (SSH
	// keyboard-interactive, password, or the maintenance session) presents a
	// Coder token; the audit layer does not distinguish the carrier method.
	MethodToken = "token"

	// Validation result values (bounded; from core.CredentialErrorKind).
	ValidationInvalid      = "invalid"
	ValidationForbidden    = "forbidden"
	ValidationWrongUser    = "wrong_identity"
	ValidationUnavailable  = "unavailable"
	ValidationIncompatible = "incompatible"
	ValidationMalformed    = "malformed"
	ValidationMissing      = "missing"
	ValidationError        = "error"

	// Store operation label values.
	StoreOpLookupKey       = "lookup_key"
	StoreOpLoadCredential  = "load_credential"
	StoreOpReplaceCred     = "replace_credential"
	StoreOpGetAccount      = "get_account"
	StoreOpClearCredential = "clear_credential"
	StoreOpMarkInvalid     = "mark_invalid"

	// Enrollment result values (bounded; CD-2 outcomes).
	EnrollmentSuccess     = "success"
	EnrollmentRejected    = "rejected"
	EnrollmentKeyConflict = "key_conflict"
	EnrollmentRateLimited = "rate_limited"
)

// Recorder is the call surface for counters/gauges outside the tunnel
// package: the SSH server records connection/auth/channel/limit events and
// the app-level wrappers record credential validations, renewals, and store
// operations. Implementations must be goroutine-safe.
type Recorder interface {
	ConnectionOpened()
	ConnectionClosed(result string)
	AuthAttempt(method, result string)
	AuthDuration(result string, d time.Duration)
	ChannelAccepted()
	ChannelRejected()
	ChannelClosed()
	LimitRejection(limit string)
	CredentialValidation(result string, d time.Duration)
	CredentialRenewal(method, result string)
	StoreOperation(operation, result string)
	Enrollment(result string)
}

// NoopRecorder satisfies Recorder with no-ops for tests and partial wiring.
type NoopRecorder struct{}

func (NoopRecorder) ConnectionOpened()                          {}
func (NoopRecorder) ConnectionClosed(string)                    {}
func (NoopRecorder) AuthAttempt(string, string)                 {}
func (NoopRecorder) AuthDuration(string, time.Duration)         {}
func (NoopRecorder) ChannelAccepted()                           {}
func (NoopRecorder) ChannelRejected()                           {}
func (NoopRecorder) ChannelClosed()                             {}
func (NoopRecorder) LimitRejection(string)                      {}
func (NoopRecorder) CredentialValidation(string, time.Duration) {}
func (NoopRecorder) CredentialRenewal(string, string)           {}
func (NoopRecorder) StoreOperation(string, string)              {}
func (NoopRecorder) Enrollment(string)                          {}

// Metrics owns the registry and every §34.2 family. It implements both
// Recorder and tunnel.Observer.
type Metrics struct {
	Registry *prometheus.Registry

	connectionsActive prometheus.Gauge
	connectionsTotal  *prometheus.CounterVec
	authAttempts      *prometheus.CounterVec
	authDuration      *prometheus.HistogramVec
	credValidations   *prometheus.CounterVec
	credValidationDur *prometheus.HistogramVec
	credRenewals      *prometheus.CounterVec
	channelsActive    prometheus.Gauge
	channelsTotal     *prometheus.CounterVec
	procsActive       prometheus.Gauge
	procExits         *prometheus.CounterVec
	tunnelBytes       *prometheus.CounterVec
	limitRejections   *prometheus.CounterVec
	storeOps          *prometheus.CounterVec
	enrollments       *prometheus.CounterVec

	// Limits usage gauges (extension beyond §34.2; §20 requires current
	// usage to be exposed). Filled by PollLimitsUsage.
	limitsUsage *prometheus.GaugeVec
	limitsMax   *prometheus.GaugeVec
}

// compile-time interface check (tunnel.Observer satisfaction is structural;
// a check here would import cycle through server's metrics dependency).
var (
	_ Recorder = (*Metrics)(nil)
	_ Recorder = NoopRecorder{}
)

// histogramBuckets are seconds; validations run against a 10s-timeout HTTP
// API and handshakes against a 30s deadline.
var histogramBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

// New builds the registry with all §34.2 families and pre-creates the
// bounded label combinations so every family is visible on /metrics even
// before the first event.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{Namespace: namespace}),
	)

	m := &Metrics{
		Registry: reg,
		connectionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "connections_active",
			Help: "Currently open outer SSH connections (any auth state).",
		}),
		connectionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "connections_total",
			Help: "Outer SSH connections by terminal result.",
		}, []string{"result"}),
		authAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "auth_attempts_total",
			Help: "SSH auth attempts by method and result.",
		}, []string{"method", "result"}),
		authDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "auth_duration_seconds",
			Help:    "SSH handshake+auth duration by result.",
			Buckets: histogramBuckets,
		}, []string{"result"}),
		credValidations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "credential_validations_total",
			Help: "Coder credential validations against the control plane by result.",
		}, []string{"result"}),
		credValidationDur: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "credential_validation_duration_seconds",
			Help:    "Coder credential validation latency by result.",
			Buckets: histogramBuckets,
		}, []string{"result"}),
		credRenewals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "credential_renewals_total",
			Help: "Credential renewal attempts by presentation method and result.",
		}, []string{"method", "result"}),
		channelsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "channels_active",
			Help: "Currently open SSH channels.",
		}),
		channelsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "channels_total",
			Help: "SSH channel open requests by result.",
		}, []string{"result"}),
		procsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "coder_processes_active",
			Help: "Currently running coder child processes.",
		}),
		procExits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "coder_process_exits_total",
			Help: "Coder child process exits by supervision class.",
		}, []string{"class"}),
		tunnelBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "tunnel_bytes_total",
			Help: "Bytes proxied between client channels and coder processes by direction.",
		}, []string{"direction"}),
		limitRejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "limit_rejections_total",
			Help: "Admissions rejected by a resource limit, by limit name.",
		}, []string{"limit"}),
		storeOps: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "store_operations_total",
			Help: "State store operations by operation and result.",
		}, []string{"operation", "result"}),
		enrollments: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "enrollments_total",
			Help: "CD-2 login@ self-enrollment outcomes by result.",
		}, []string{"result"}),
		limitsUsage: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "limits_usage",
			Help: "Current usage of each §20 resource limit (sums per-entity maps).",
		}, []string{"limit"}),
		limitsMax: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "limits_max",
			Help: "Configured maximum of each §20 resource limit.",
		}, []string{"limit"}),
	}

	reg.MustRegister(
		m.connectionsActive, m.connectionsTotal, m.authAttempts, m.authDuration,
		m.credValidations, m.credValidationDur, m.credRenewals,
		m.channelsActive, m.channelsTotal, m.procsActive, m.procExits,
		m.tunnelBytes, m.limitRejections, m.storeOps, m.enrollments, m.limitsUsage, m.limitsMax,
	)
	m.preCreateSeries()
	return m
}

// preCreateSeries instantiates the known bounded label combinations so all
// §34.2 families appear in /metrics output from process start.
func (m *Metrics) preCreateSeries() {
	for _, r := range []string{ResultSuccess, ResultFailure, ResultRejected} {
		m.connectionsTotal.WithLabelValues(r)
	}
	m.channelsTotal.WithLabelValues("accepted")
	m.channelsTotal.WithLabelValues("rejected")

	for _, method := range []string{MethodPublicKey, MethodPassword, MethodKeyboardInteractive, MethodNone, MethodOther} {
		for _, r := range []string{ResultSuccess, ResultFailure} {
			m.authAttempts.WithLabelValues(method, r)
		}
	}
	for _, r := range []string{ResultSuccess, ResultFailure} {
		m.authDuration.WithLabelValues(r)
	}
	for _, r := range []string{
		ResultSuccess, ValidationInvalid, ValidationForbidden, ValidationWrongUser,
		ValidationUnavailable, ValidationIncompatible, ValidationMalformed,
		ValidationMissing, ValidationError,
	} {
		m.credValidations.WithLabelValues(r)
		m.credValidationDur.WithLabelValues(r)
	}
	for _, r := range []string{ResultSuccess, ResultFailure, ResultWrongUser} {
		m.credRenewals.WithLabelValues(MethodToken, r)
	}
	for _, class := range []string{
		"ok",
		"TUNNEL_CODER_EXITED", "TUNNEL_START_TIMEOUT",
		"TUNNEL_CANCELLED", "TUNNEL_STREAM_FAILED",
	} {
		m.procExits.WithLabelValues(class)
	}
	for _, dir := range []string{DirUp, DirDown} {
		m.tunnelBytes.WithLabelValues(dir)
	}
	for _, lim := range limitNames() {
		m.limitRejections.WithLabelValues(lim)
	}
	for _, op := range []string{
		StoreOpLookupKey, StoreOpLoadCredential, StoreOpReplaceCred,
		StoreOpGetAccount, StoreOpClearCredential, StoreOpMarkInvalid,
	} {
		for _, r := range []string{ResultSuccess, ResultFailure} {
			m.storeOps.WithLabelValues(op, r)
		}
	}
	for _, r := range []string{EnrollmentSuccess, EnrollmentRejected, EnrollmentKeyConflict, EnrollmentRateLimited} {
		m.enrollments.WithLabelValues(r)
	}
}

// limitNames is the bounded set of limit label values (limits.Reason values
// plus the usage-gauge names; kept in sync with internal/limits).
func limitNames() []string {
	return []string{
		string(limits.ReasonGlobalConn),
		string(limits.ReasonHandshake),
		string(limits.ReasonIPConn),
		string(limits.ReasonKeyConn),
		string(limits.ReasonAccountConn),
		string(limits.ReasonChannelConn),
		string(limits.ReasonChannelAccount),
		string(limits.ReasonCoderProcess),
		string(limits.ReasonCoderAPI),
		string(limits.ReasonPreAuthIP),
		string(limits.ReasonUnknownKeyAttempt),
		string(limits.ReasonRenewalRate),
	}
}

// Handler serves /metrics on a dedicated mux (never the default mux, so no
// pprof or other ambient handlers can leak onto this listener, §33.3).
func (m *Metrics) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	}))
	return mux
}

// --- Recorder implementation (server + app wrappers) ---

func (m *Metrics) ConnectionOpened() { m.connectionsActive.Inc() }

func (m *Metrics) ConnectionClosed(result string) {
	m.connectionsActive.Dec()
	m.connectionsTotal.WithLabelValues(normalizeResult(result)).Inc()
}

func (m *Metrics) AuthAttempt(method, result string) {
	m.authAttempts.WithLabelValues(normalizeMethod(method), normalizeResult(result)).Inc()
}

func (m *Metrics) AuthDuration(result string, d time.Duration) {
	m.authDuration.WithLabelValues(normalizeResult(result)).Observe(d.Seconds())
}

func (m *Metrics) ChannelAccepted() {
	m.channelsActive.Inc()
	m.channelsTotal.WithLabelValues("accepted").Inc()
}

func (m *Metrics) ChannelRejected() {
	m.channelsTotal.WithLabelValues("rejected").Inc()
}

func (m *Metrics) ChannelClosed() { m.channelsActive.Dec() }

func (m *Metrics) LimitRejection(limit string) {
	m.limitRejections.WithLabelValues(normalizeLimit(limit)).Inc()
}

func (m *Metrics) CredentialValidation(result string, d time.Duration) {
	r := normalizeValidation(result)
	m.credValidations.WithLabelValues(r).Inc()
	m.credValidationDur.WithLabelValues(r).Observe(d.Seconds())
}

func (m *Metrics) CredentialRenewal(method, result string) {
	if method != MethodToken {
		method = MethodToken
	}
	switch result {
	case ResultSuccess, ResultFailure, ResultWrongUser:
	default:
		result = ResultFailure
	}
	m.credRenewals.WithLabelValues(method, result).Inc()
}

func (m *Metrics) StoreOperation(operation, result string) {
	m.storeOps.WithLabelValues(normalizeStoreOp(operation), normalizeResult(result)).Inc()
}

func (m *Metrics) Enrollment(result string) {
	m.enrollments.WithLabelValues(normalizeEnrollment(result)).Inc()
}

// --- tunnel.Observer implementation ---

// ProcessStarted increments the active coder-process gauge.
func (m *Metrics) ProcessStarted() { m.procsActive.Inc() }

// ProcessExited decrements the gauge and counts the exit by supervision
// class (core.TUNNEL_* code; empty class means a clean exit).
func (m *Metrics) ProcessExited(class string) {
	m.procsActive.Dec()
	if class == "" {
		class = "ok"
	}
	m.procExits.WithLabelValues(class).Inc()
}

// TunnelBytes counts proxied bytes by direction ("up"/"down").
func (m *Metrics) TunnelBytes(dir string, n int) {
	if dir != DirUp && dir != DirDown {
		return
	}
	m.tunnelBytes.WithLabelValues(dir).Add(float64(n))
}

// ActiveGauge is intentionally a no-op: the supervisor calls it with 0 after
// every tunnel exit, which would clobber the count of concurrent tunnels.
// The active gauge is derived from ProcessStarted/ProcessExited pairs
// instead (T24 decision; see learnings).
func (m *Metrics) ActiveGauge(int) {}

// --- Limits usage polling (§20: expose current usage as metrics) ---

// PollLimitsUsage samples counters.Usage() every interval (<=0 selects 5s)
// into the limits_usage/limits_max gauges until ctx is done. Per-entity
// limits are exported as the sum across entities; the tracked-entity count
// is intentionally not exported (unbounded map sizes are not usage).
func (m *Metrics) PollLimitsUsage(ctx context.Context, c *limits.Counters, maxima map[string]int, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	for name, max := range maxima {
		m.limitsMax.WithLabelValues(name).Set(float64(max))
	}
	sample := func() {
		u := c.Usage()
		m.limitsUsage.WithLabelValues(string(limits.ReasonGlobalConn)).Set(float64(u.GlobalConns))
		m.limitsUsage.WithLabelValues(string(limits.ReasonHandshake)).Set(float64(u.Handshakes))
		m.limitsUsage.WithLabelValues(string(limits.ReasonIPConn)).Set(float64(sumMap(u.IPs)))
		m.limitsUsage.WithLabelValues(string(limits.ReasonKeyConn)).Set(float64(sumUUIDMap(u.Keys)))
		m.limitsUsage.WithLabelValues(string(limits.ReasonAccountConn)).Set(float64(sumUUIDMap(u.Accounts)))
		m.limitsUsage.WithLabelValues(string(limits.ReasonChannelConn)).Set(float64(sumMap(u.Channels)))
		m.limitsUsage.WithLabelValues(string(limits.ReasonChannelAccount)).Set(float64(sumUUIDMap(u.ChannelAccounts)))
		m.limitsUsage.WithLabelValues(string(limits.ReasonCoderProcess)).Set(float64(u.CoderProcesses))
		m.limitsUsage.WithLabelValues(string(limits.ReasonCoderAPI)).Set(float64(u.CoderAPIRequests))
	}
	sample()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sample()
		}
	}
}

func sumMap[V ~int](m map[string]V) int {
	total := 0
	for _, v := range m {
		total += int(v)
	}
	return total
}

func sumUUIDMap[K comparable, V ~int](m map[K]V) int {
	total := 0
	for _, v := range m {
		total += int(v)
	}
	return total
}

// --- label normalization (cardinality guards) ---

func normalizeResult(r string) string {
	switch r {
	case ResultSuccess, ResultFailure, ResultRejected:
		return r
	default:
		return ResultFailure
	}
}

func normalizeMethod(method string) string {
	switch method {
	case MethodPublicKey, MethodNone:
		return method
	case "password":
		return MethodPassword
	case "keyboard-interactive", MethodKeyboardInteractive:
		return MethodKeyboardInteractive
	default:
		return MethodOther
	}
}

func normalizeLimit(l string) string {
	for _, name := range limitNames() {
		if l == name {
			return l
		}
	}
	return "other"
}

func normalizeValidation(r string) string {
	switch r {
	case ResultSuccess, ValidationInvalid, ValidationForbidden, ValidationWrongUser,
		ValidationUnavailable, ValidationIncompatible, ValidationMalformed,
		ValidationMissing:
		return r
	default:
		return ValidationError
	}
}

func normalizeStoreOp(op string) string {
	switch op {
	case StoreOpLookupKey, StoreOpLoadCredential, StoreOpReplaceCred,
		StoreOpGetAccount, StoreOpClearCredential, StoreOpMarkInvalid:
		return op
	default:
		return "other"
	}
}

func normalizeEnrollment(r string) string {
	switch r {
	case EnrollmentSuccess, EnrollmentKeyConflict, EnrollmentRateLimited:
		return r
	default:
		return EnrollmentRejected
	}
}
