package app_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/HamStudy/coder-ssh-gateway/internal/app"
	"github.com/HamStudy/coder-ssh-gateway/internal/config"
)

// TestServeEnvAddressOverrides asserts the assembled listeners bind the
// CSGW_* env values, not the config-file values: the env-provided health and
// SSH ports answer while the config-file ports refuse connections.
func TestServeEnvAddressOverrides(t *testing.T) {
	f := newCLIFixture(t, true)

	cfgSSHPort, cfgMetricsPort, cfgHealthPort := freePort(t), freePort(t), freePort(t)
	extra := fmt.Sprintf("listen:\n  address: 127.0.0.1:%d\nobservability:\n  metrics_address: 127.0.0.1:%d\n  health_address: 127.0.0.1:%d\n",
		cfgSSHPort, cfgMetricsPort, cfgHealthPort)
	cfgBytes, err := os.ReadFile(f.configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if err := os.WriteFile(f.configPath, append(cfgBytes, []byte(extra)...), 0o600); err != nil {
		t.Fatalf("extend config: %v", err)
	}

	envSSHPort, envMetricsPort, envHealthPort := freePort(t), freePort(t), freePort(t)
	t.Setenv(config.EnvListenAddress, fmt.Sprintf("127.0.0.1:%d", envSSHPort))
	t.Setenv(config.EnvMetricsAddress, fmt.Sprintf("127.0.0.1:%d", envMetricsPort))
	t.Setenv(config.EnvHealthAddress, fmt.Sprintf("127.0.0.1:%d", envHealthPort))

	ctx, cancel := context.WithCancel(context.Background())
	var outBuf, errBuf bytes.Buffer
	codeCh := make(chan int, 1)
	go func() {
		codeCh <- app.Run(ctx, []string{"--state-dir", f.dir, "serve"}, nil, &outBuf, &errBuf)
	}()

	waitHTTPReady(t, fmt.Sprintf("http://127.0.0.1:%d/livez", envHealthPort))

	assertRefused(t, cfgHealthPort)
	assertRefused(t, cfgMetricsPort)
	assertRefused(t, cfgSSHPort)

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", envSSHPort), 2*time.Second)
	if err != nil {
		t.Fatalf("env SSH port %d not listening: %v", envSSHPort, err)
	}
	conn.Close()
	if got := curlStatus(t, fmt.Sprintf("http://127.0.0.1:%d/metrics", envMetricsPort)); got != "200" {
		t.Errorf("env metrics /metrics status = %s, want 200", got)
	}

	cancel()
	select {
	case code := <-codeCh:
		if code != 0 {
			t.Errorf("serve exit code = %d, want 0\nstderr: %s", code, errBuf.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not exit within 30s of cancellation")
	}
}

// TestServeFlagAddressOverrides asserts the real serve path applies global
// address flags after environment overrides for all three listeners.
func TestServeFlagAddressOverrides(t *testing.T) {
	f := newCLIFixture(t, true)

	cfgSSHPort, cfgMetricsPort, cfgHealthPort := freePort(t), freePort(t), freePort(t)
	extra := fmt.Sprintf("listen:\n  address: 127.0.0.1:%d\nobservability:\n  metrics_address: 127.0.0.1:%d\n  health_address: 127.0.0.1:%d\n",
		cfgSSHPort, cfgMetricsPort, cfgHealthPort)
	cfgBytes, err := os.ReadFile(f.configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if err := os.WriteFile(f.configPath, append(cfgBytes, []byte(extra)...), 0o600); err != nil {
		t.Fatalf("extend config: %v", err)
	}

	envSSHPort, envMetricsPort, envHealthPort := freePort(t), freePort(t), freePort(t)
	t.Setenv(config.EnvListenAddress, fmt.Sprintf("127.0.0.1:%d", envSSHPort))
	t.Setenv(config.EnvMetricsAddress, fmt.Sprintf("127.0.0.1:%d", envMetricsPort))
	t.Setenv(config.EnvHealthAddress, fmt.Sprintf("127.0.0.1:%d", envHealthPort))

	flagSSHPort, flagMetricsPort, flagHealthPort := freePort(t), freePort(t), freePort(t)
	flagSSH := fmt.Sprintf("127.0.0.1:%d", flagSSHPort)
	flagMetrics := fmt.Sprintf("127.0.0.1:%d", flagMetricsPort)
	flagHealth := fmt.Sprintf("127.0.0.1:%d", flagHealthPort)
	ctx, cancel := context.WithCancel(context.Background())
	var outBuf, errBuf bytes.Buffer
	codeCh := make(chan int, 1)
	go func() {
		codeCh <- app.Run(ctx, []string{
			"--state-dir", f.dir,
			"--listen-address", flagSSH,
			"--metrics-address=" + flagMetrics,
			"--health-address", flagHealth,
			"serve",
		}, nil, &outBuf, &errBuf)
	}()

	waitHTTPReady(t, fmt.Sprintf("http://127.0.0.1:%d/livez", flagHealthPort))
	for _, port := range []int{cfgSSHPort, cfgMetricsPort, cfgHealthPort, envSSHPort, envMetricsPort, envHealthPort} {
		assertRefused(t, port)
	}
	conn, err := net.DialTimeout("tcp", flagSSH, 2*time.Second)
	if err != nil {
		t.Fatalf("flag SSH address %s not listening: %v", flagSSH, err)
	}
	conn.Close()
	if got := curlStatus(t, "http://"+flagMetrics+"/metrics"); got != "200" {
		t.Errorf("flag metrics /metrics status = %s, want 200", got)
	}

	cancel()
	select {
	case code := <-codeCh:
		if code != 0 {
			t.Errorf("serve exit code = %d, want 0\nstderr: %s", code, errBuf.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not exit within 30s of cancellation")
	}
}

func assertRefused(t *testing.T, port int) {
	t.Helper()
	// Shutdown releases the listeners asynchronously; allow a grace window
	// before declaring a leak.
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
		if err != nil {
			return
		}
		conn.Close()
		if time.Now().After(deadline) {
			t.Errorf("overridden port %d is listening after shutdown", port)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}
