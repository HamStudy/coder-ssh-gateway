package app

import (
	"context"
	"testing"

	"github.com/HamStudy/coder-ssh-gateway/internal/audit"
	"github.com/HamStudy/coder-ssh-gateway/internal/metrics"
	"github.com/HamStudy/coder-ssh-gateway/internal/sshauth"
)

// enrollmentMetricValue reads the enrollments_total series for one result
// label out of the registry (the counter fields are package-private).
func enrollmentMetricValue(t *testing.T, m *metrics.Metrics, result string) float64 {
	t.Helper()
	mfs, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "coder_ssh_gateway_enrollments_total" {
			continue
		}
		for _, mt := range mf.GetMetric() {
			for _, lp := range mt.GetLabel() {
				if lp.GetName() == "result" && lp.GetValue() == result {
					return mt.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func TestAuditMetricBridgeEnrollmentEvents(t *testing.T) {
	m := metrics.New()
	inner := audit.NewInMemoryLogger()
	bridge := &auditMetricBridge{inner: inner, rec: m}

	record := func(eventType, result, detail string) {
		t.Helper()
		if err := bridge.Record(context.Background(), audit.Event{
			EventType:  eventType,
			Result:     result,
			DetailCode: detail,
		}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	record(sshauth.EventTypeEnrollmentSuccess, sshauth.ResultSuccess, sshauth.DetailEnrollmentAccountCreated)
	record(sshauth.EventTypeEnrollmentRejected, sshauth.ResultFailure, sshauth.DetailEnrollmentKeyAlreadyLinked)
	record(sshauth.EventTypeEnrollmentRejected, sshauth.ResultFailure, sshauth.DetailEnrollmentRateLimited)
	record(sshauth.EventTypeEnrollmentRejected, sshauth.ResultFailure, sshauth.DetailEnrollmentAttemptsExhausted)
	record(sshauth.EventTypeEnrollmentRejected, sshauth.ResultFailure, "AUTH_CREDENTIAL_UNAUTHORIZED")
	record(sshauth.EventTypeAuthRejected, sshauth.ResultFailure, "AUTH_UNKNOWN_KEY")

	checks := []struct {
		result string
		want   float64
	}{
		{metrics.EnrollmentSuccess, 1},
		{metrics.EnrollmentKeyConflict, 1},
		{metrics.EnrollmentRateLimited, 1},
		{metrics.EnrollmentRejected, 2},
	}
	for _, c := range checks {
		if got := enrollmentMetricValue(t, m, c.result); got != c.want {
			t.Errorf("enrollments_total{result=%q} = %v, want %v", c.result, got, c.want)
		}
	}
	if n := len(inner.Events()); n != 6 {
		t.Errorf("inner audit events = %d, want 6 (all events pass through)", n)
	}
}
