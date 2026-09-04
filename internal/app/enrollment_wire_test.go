package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/app"
	"github.com/taxilian/coder-ssh-gateway/internal/config"
	"github.com/taxilian/coder-ssh-gateway/internal/sshauth"
)

// bannerCapture is a race-safe BannerCallback recorder.
type bannerCapture struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *bannerCapture) cb(message string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.WriteString(message)
	b.buf.WriteString("\n")
	return nil
}

func (b *bannerCapture) text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// enrollmentServer boots the real app assembly (Build + ServeOn) over the
// CLI-initialized fixture state dir. Metrics/health aux listeners are off.
type enrollmentServer struct {
	built  *app.Built
	addr   string
	cancel context.CancelFunc
	errCh  chan error
}

func startEnrollmentServer(t *testing.T, f *cliFixture, mutate func(*config.Config)) *enrollmentServer {
	t.Helper()
	cfg, err := config.Parse(f.configPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	config.ApplyStateDir(cfg, f.dir)
	cfg.Observability.MetricsAddress = ""
	cfg.Observability.HealthAddress = ""
	if mutate != nil {
		mutate(cfg)
	}
	built, err := app.Build(cfg, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		built.Close()
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	es := &enrollmentServer{built: built, addr: ln.Addr().String(), cancel: cancel, errCh: make(chan error, 1)}
	go func() {
		es.errCh <- built.ServeOn(ctx, ln)
	}()
	return es
}

func (es *enrollmentServer) shutdown(t *testing.T) {
	t.Helper()
	es.cancel()
	select {
	case err := <-es.errCh:
		if err != nil {
			t.Errorf("ServeOn: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("ServeOn did not return within 10s of cancel")
	}
	if err := es.built.Close(); err != nil {
		t.Errorf("built close: %v", err)
	}
}

func newEnrollmentSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

func dialEnrollment(t *testing.T, addr, user string, banners *bannerCapture, auth ...ssh.AuthMethod) (*ssh.Client, error) {
	t.Helper()
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		BannerCallback:  banners.cb,
		Timeout:         10 * time.Second,
	})
}

// enrollmentMetricValue reads one enrollments_total series by result label.
func enrollmentMetricValue(t *testing.T, es *enrollmentServer, result string) float64 {
	t.Helper()
	mfs, err := es.built.Metrics.Registry.Gather()
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

// auditLogText concatenates every audit JSONL file under the state dir.
func auditLogText(t *testing.T, f *cliFixture) string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(f.dir, "audit"))
	if err != nil {
		t.Fatalf("read audit dir: %v", err)
	}
	var sb strings.Builder
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(f.dir, "audit", e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		sb.Write(raw)
	}
	return sb.String()
}

// Full assembly: a fresh key + valid token against init@ enrolls end-to-end
// (account created, key linked, credential stored), the success banner
// carries the Coder username, the server closes the connection (§13.6), and
// the enrollment metric counts the success.
func TestServeEnrollmentEnabledEndToEnd(t *testing.T) {
	f := newCLIFixture(t, false)
	token := "e2e-enroll-token-0123456789abcdef"
	f.coder.addToken(token, f.coderUserID, "taxilian")

	es := startEnrollmentServer(t, f, nil)
	defer es.shutdown(t)

	signer := newEnrollmentSigner(t)
	banners := &bannerCapture{}
	client, err := dialEnrollment(t, es.addr, "init", banners, ssh.PublicKeys(signer), ssh.Password(token))
	if err != nil {
		t.Fatalf("enrollment dial: %v", err)
	}
	defer client.Close()

	if got := banners.text(); !strings.Contains(got, "Enrolled. Coder user taxilian") {
		t.Errorf("missing success banner: %q", got)
	}
	if strings.Contains(banners.text(), token) {
		t.Error("banner leaks token material")
	}

	// §13.6: the server closes the connection right after enrollment.
	done := make(chan error, 1)
	go func() { done <- client.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("server did not close the connection after enrollment")
	}

	accounts, err := es.built.Store.ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	accountID := ""
	for _, a := range accounts {
		if a.CoderUserID != nil && *a.CoderUserID == f.coderUserID {
			accountID = a.ID.String()
			break
		}
	}
	if accountID == "" {
		t.Fatal("no account created for the token's Coder user")
	}
	owner, exists, err := es.built.Store.KeyDigestExists(sshauth.KeyDigestHex(signer.PublicKey()))
	if err != nil || !exists {
		t.Fatalf("key digest not stored: exists=%v err=%v", exists, err)
	}
	if owner.String() != accountID {
		t.Errorf("key digest owner = %v, want %v", owner, accountID)
	}

	if got := enrollmentMetricValue(t, es, "success"); got != 1 {
		t.Errorf("enrollments_total{success} = %v, want 1", got)
	}
	if got := auditLogText(t, f); !strings.Contains(got, "enrollment_success") {
		t.Error("audit log missing enrollment_success event")
	}
}

// Disabled enrollment: init@ rejects byte-identically to an unknown
// username (§35 uniformity), nothing is stored.
func TestServeEnrollmentDisabledUniformReject(t *testing.T) {
	f := newCLIFixture(t, false)
	token := "e2e-enroll-token-0123456789abcdef"
	f.coder.addToken(token, f.coderUserID, "taxilian")

	es := startEnrollmentServer(t, f, func(cfg *config.Config) {
		cfg.Enrollment.Enabled = false
	})
	defer es.shutdown(t)

	dialErr := func(user string) string {
		banners := &bannerCapture{}
		client, err := dialEnrollment(t, es.addr, user, banners,
			ssh.PublicKeys(newEnrollmentSigner(t)), ssh.Password(token))
		if client != nil {
			client.Close()
		}
		if err == nil {
			t.Fatalf("expected auth failure for user %q", user)
		}
		if strings.Contains(banners.text(), "enrollment") {
			t.Errorf("user %q: enrollment banner leaked: %q", user, banners.text())
		}
		return err.Error()
	}

	unknownRef := dialErr("nosuchuser")
	if got := dialErr("init"); got != unknownRef {
		t.Errorf("disabled init@ error differs from unknown username:\n  %q\n  %q", got, unknownRef)
	}

	accounts, err := es.built.Store.ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	for _, a := range accounts {
		if a.CoderUserID != nil && *a.CoderUserID == f.coderUserID {
			t.Error("disabled enrollment must not create an account")
		}
	}
	if got := auditLogText(t, f); strings.Contains(got, "enrollment_") {
		t.Errorf("disabled enrollment must not emit enrollment audit events:\n%s", got)
	}
}

// Per-IP enrollment bound (CD-2 §20): the unknown-key bucket (10/min)
// gates token attempts before any account exists; once exhausted the flow
// refuses before prompting and audits ENROLLMENT_RATE_LIMITED.
func TestServeEnrollmentRateLimited(t *testing.T) {
	f := newCLIFixture(t, false)
	f.coder.addToken("e2e-bad-token-0123456789abcdef0", f.coderUserID, "taxilian")

	es := startEnrollmentServer(t, f, nil)
	defer es.shutdown(t)

	// Each failed connection consumes the gate at the verified stage and
	// again at the password attempt: five connections drain the bucket of
	// ten, the sixth is refused before any prompt.
	for i := 0; i < 6; i++ {
		banners := &bannerCapture{}
		client, err := dialEnrollment(t, es.addr, "init", banners,
			ssh.PublicKeys(newEnrollmentSigner(t)), ssh.Password("wrong-token-0123456789abcdefgh"))
		if client != nil {
			client.Close()
		}
		if err == nil {
			t.Fatalf("dial %d: expected auth failure", i+1)
		}
		if i == 5 && strings.Contains(banners.text(), "enrollment") {
			t.Errorf("rate-limited dial must not offer the enrollment banner: %q", banners.text())
		}
	}

	auditText := auditLogText(t, f)
	if !strings.Contains(auditText, "ENROLLMENT_RATE_LIMITED") {
		t.Errorf("audit log missing ENROLLMENT_RATE_LIMITED:\n%s", auditText)
	}
	if got := enrollmentMetricValue(t, es, "rate_limited"); got < 1 {
		t.Errorf("enrollments_total{rate_limited} = %v, want >= 1", got)
	}

	accounts, err := es.built.Store.ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	for _, a := range accounts {
		if a.CoderUserID != nil && *a.CoderUserID == f.coderUserID {
			t.Error("rate-limited enrollment must not create an account")
		}
	}
}
