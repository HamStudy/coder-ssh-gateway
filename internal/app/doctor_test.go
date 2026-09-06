package app

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/taxilian/coder-ssh-gateway/internal/config"
	"github.com/taxilian/coder-ssh-gateway/internal/testutil"
)

func TestWorkspaceProbeInvokesConfiguredCoderBinary(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		Deployment: config.Deployment{
			ID:                      "primary",
			CoderURL:                "https://coder.example.com",
			CoderBinary:             testutil.BuildFakeCoder(t),
			CoderGlobalConfig:       filepath.Join(dir, "coder-config"),
			WorkingDirectory:        dir,
			Autostart:               true,
			Wait:                    "auto",
			WorkspaceConnectTimeout: config.Duration(5 * time.Second),
		},
	}
	var stdout bytes.Buffer
	report := doctorReport{c: &cli{stdout: &stdout}}

	report.checkWorkspaceProbe(cfg, "examtools-docs", "account-present", []byte("doctor-probe-test-token"))

	if report.failures != 0 {
		t.Fatalf("probe failures = %d, want 0; output:\n%s", report.failures, stdout.String())
	}
	if output := stdout.String(); !strings.Contains(output, "PASS probe-workspace:") ||
		!strings.Contains(output, "produced output") {
		t.Fatalf("probe output does not report success:\n%s", output)
	}
}
