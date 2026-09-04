package app_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/app"
	"github.com/taxilian/coder-ssh-gateway/internal/testutil"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func curl(t *testing.T, url string) string {
	t.Helper()
	out, err := exec.Command("curl", "-sS", "-i", "--max-time", "5", url).CombinedOutput()
	if err != nil {
		t.Fatalf("curl %s: %v\n%s", url, err, out)
	}
	return string(out)
}

func curlStatus(t *testing.T, url string) string {
	t.Helper()
	out, err := exec.Command("curl", "-sS", "-o", os.DevNull, "-w", "%{http_code}", "--max-time", "5", url).CombinedOutput()
	if err != nil {
		t.Fatalf("curl %s: %v\n%s", url, err, out)
	}
	return string(out)
}

func waitHTTPReady(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s did not answer 200 within 5s", url)
}

func pgrepFakeCoder() string {
	out, _ := exec.Command("pgrep", "-fa", "fake-coder").Output()
	return strings.TrimSpace(string(out))
}

// TestOpsQA is the hands-on §32/§33/§34.2 verification: boot `serve`
// end-to-end against a TLS stub Coder, enroll account+key+credential, probe
// the health and metrics endpoints with real curl, then cancel mid-tunnel
// (SIGTERM equivalent — main wraps Run's ctx in signal.NotifyContext) and
// verify exit code 0, no orphaned coder children, and flock release.
// Evidence is written to .sisyphus/evidence/task-24-*.txt.
func TestOpsQA(t *testing.T) {
	evidenceDir := filepath.Join("..", "..", ".sisyphus", "evidence")

	f := newCLIFixture(t, true)
	fakeBin := testutil.BuildFakeCoder(t)
	f.writeConfig(t, fakeBin)

	sshPort, metricsPort, healthPort := freePort(t), freePort(t), freePort(t)
	extra := fmt.Sprintf("listen:\n  address: 127.0.0.1:%d\nobservability:\n  metrics_address: 127.0.0.1:%d\n  health_address: 127.0.0.1:%d\n",
		sshPort, metricsPort, healthPort)
	cfgBytes, err := os.ReadFile(f.configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if err := os.WriteFile(f.configPath, append(cfgBytes, []byte(extra)...), 0o600); err != nil {
		t.Fatalf("extend config: %v", err)
	}

	acctID := f.addAccount(t, "ops qa account")
	signer, pubPath, _ := genKeyPair(t, f.dir, "opsqa.pub")
	code, out, errOut := runCLI(t, "", "--state-dir", f.dir, "admin", "key", "add",
		"--account", acctID.String(), "--file", pubPath, "--label", "ops qa key")
	if code != 0 {
		t.Fatalf("key add: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	token := "opsqa-token-0123456789abcdef"
	f.coder.addToken(token, f.coderUserID, "taxilian")
	code, out, errOut = runCLI(t, token+"\n", "--state-dir", f.dir, "admin", "credential", "set",
		"--account", acctID.String(), "--stdin")
	if code != 0 {
		t.Fatalf("credential set: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}

	livezURL := fmt.Sprintf("http://127.0.0.1:%d/livez", healthPort)
	readyzURL := fmt.Sprintf("http://127.0.0.1:%d/readyz", healthPort)
	metricsURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsPort)

	serve := func(ctx context.Context) (chan int, *bytes.Buffer, *bytes.Buffer) {
		var outBuf, errBuf bytes.Buffer
		codeCh := make(chan int, 1)
		go func() {
			codeCh <- app.Run(ctx, []string{"--state-dir", f.dir, "serve"}, nil, &outBuf, &errBuf)
		}()
		return codeCh, &outBuf, &errBuf
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	codeCh, outBuf, errBuf := serve(ctx1)
	waitHTTPReady(t, livezURL)

	// --- health evidence (§33) ---
	var healthEvidence strings.Builder
	fmt.Fprintf(&healthEvidence, "$ curl -i %s\n%s\n", livezURL, curl(t, livezURL))
	fmt.Fprintf(&healthEvidence, "$ curl -i %s\n%s\n", readyzURL, curl(t, readyzURL))
	if got := curlStatus(t, livezURL); got != "200" {
		t.Errorf("/livez status = %s, want 200", got)
	}
	readyzBody := curl(t, readyzURL)
	if !strings.Contains(readyzBody, "200") || !strings.Contains(readyzBody, `"coder_reachable":true`) {
		t.Errorf("/readyz missing 200/coder_reachable=true:\n%s", readyzBody)
	}
	for _, check := range []string{`"host_key":"ok"`, `"encryption":"ok"`, `"store":"ok"`, `"listener":"up"`, `"supervisor":"ok"`} {
		if !strings.Contains(readyzBody, check) {
			t.Errorf("/readyz missing check %s:\n%s", check, readyzBody)
		}
	}
	if err := os.WriteFile(filepath.Join(evidenceDir, "task-24-health.txt"), []byte(healthEvidence.String()), 0o644); err != nil {
		t.Fatalf("write health evidence: %v", err)
	}

	// --- metrics evidence (§34.2) ---
	var metricsBody string
	metricsDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(metricsDeadline) {
		metricsBody = curl(t, metricsURL)
		if strings.Contains(metricsBody, "coder_ssh_gateway_limits_max{") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	families := map[string]bool{}
	for _, line := range strings.Split(metricsBody, "\n") {
		if strings.HasPrefix(line, "# TYPE coder_ssh_gateway_") {
			families[strings.Fields(line)[2]] = true
		}
	}
	if len(families) < 10 {
		t.Errorf("/metrics exposes %d coder_ssh_gateway_ families, want >= 10", len(families))
	}
	var metricsEvidence strings.Builder
	fmt.Fprintf(&metricsEvidence, "$ curl %s | grep '^# TYPE coder_ssh_gateway_'\n", metricsURL)
	for fam := range families {
		fmt.Fprintf(&metricsEvidence, "%s\n", fam)
	}
	fmt.Fprintf(&metricsEvidence, "family count: %d\n\nsample series:\n", len(families))
	for _, line := range strings.Split(metricsBody, "\n") {
		if strings.HasPrefix(line, "coder_ssh_gateway_connections_active") ||
			strings.HasPrefix(line, "coder_ssh_gateway_limits_max") {
			fmt.Fprintf(&metricsEvidence, "%s\n", line)
		}
	}
	if err := os.WriteFile(filepath.Join(evidenceDir, "task-24-metrics.txt"), []byte(metricsEvidence.String()), 0o644); err != nil {
		t.Fatalf("write metrics evidence: %v", err)
	}

	// --- establish a fake tunnel, then TERM mid-tunnel (§32) ---
	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), &ssh.ClientConfig{
		User:            "coder",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("SSH auth to serve: %v", err)
	}
	payload := ssh.Marshal(&struct {
		DestAddr string
		DestPort uint32
		OrigAddr string
		OrigPort uint32
	}{"examtools-docs.coder-gateway.example.com", 22, "127.0.0.1", 2222})
	ch, _, err := client.OpenChannel("direct-tcpip", payload)
	if err != nil {
		t.Fatalf("open tunnel channel: %v", err)
	}
	tunnelDeadline := time.Now().Add(5 * time.Second)
	for pgrepFakeCoder() == "" && time.Now().Before(tunnelDeadline) {
		time.Sleep(50 * time.Millisecond)
	}
	midTunnel := pgrepFakeCoder()
	if midTunnel == "" {
		t.Fatal("fake coder child never appeared for the open tunnel")
	}

	cancel1() // SIGTERM equivalent
	var exitCode int
	select {
	case exitCode = <-codeCh:
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not exit within 30s of cancellation")
	}
	client.Close()
	ch.Close()
	postExitProcs := pgrepFakeCoder()

	var shutdownEvidence strings.Builder
	fmt.Fprintf(&shutdownEvidence, "mid-tunnel child processes (pgrep -fa fake-coder):\n%s\n\n", midTunnel)
	fmt.Fprintf(&shutdownEvidence, "serve exit code after cancel (SIGTERM equivalent): %d\n\n", exitCode)
	fmt.Fprintf(&shutdownEvidence, "post-exit child processes (pgrep -fa fake-coder):\n%s\n\n", postExitProcs)
	fmt.Fprintf(&shutdownEvidence, "serve stdout:\n%s\n\nserve stderr:\n%s\n", outBuf.String(), errBuf.String())
	if exitCode != 0 {
		t.Errorf("serve exit code = %d, want 0", exitCode)
	}
	if postExitProcs != "" {
		t.Errorf("orphan coder children after shutdown:\n%s", postExitProcs)
	}

	// flock released: a second serve must start and answer /livez.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	codeCh2, _, errBuf2 := serve(ctx2)
	waitHTTPReady(t, livezURL)
	fmt.Fprintf(&shutdownEvidence, "second serve /livez status (lock released): %s\n", curlStatus(t, livezURL))
	cancel2()
	select {
	case code2 := <-codeCh2:
		fmt.Fprintf(&shutdownEvidence, "second serve exit code: %d\n", code2)
		if code2 != 0 {
			t.Errorf("second serve exit = %d, want 0\nstderr: %s", code2, errBuf2.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("second serve did not exit")
	}

	if err := os.WriteFile(filepath.Join(evidenceDir, "task-24-shutdown.txt"), []byte(shutdownEvidence.String()), 0o644); err != nil {
		t.Fatalf("write shutdown evidence: %v", err)
	}
	t.Logf("evidence written to %s: task-24-health.txt, task-24-metrics.txt, task-24-shutdown.txt", evidenceDir)
}
