package server_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/testleaks"
)

// The enrollment goodbye is delivered on the client's FIRST session channel
// after the forced-reconnect close (§13.6): goodbye text on stderr and
// exit-status 0, so mobile clients see a clean close instead of an EOF
// error. The deadline path (client opens no session) is covered by the app
// e2e; this test covers the delivery path.

func TestEnrollmentGoodbyeDeliveredOnSessionChannel(t *testing.T) {
	defer testleaks.Verify(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	ts := startTestServer(t, f, nil)
	defer ts.shutdown(t)

	_, freshPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	fresh, err := ssh.NewSignerFromKey(freshPrivate)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	client, err := dialGateway(ts.addr(), "login", ssh.PublicKeys(fresh), ssh.Password("enroll-token-0123456789abcdef"))
	if err != nil {
		t.Fatalf("enrollment dial: %v", err)
	}

	// Open the session immediately, inside the goodbye's delivery window.
	ch, _, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("session open after enrollment: %v", err)
	}

	stderr, err := io.ReadAll(ch.Stderr())
	if err != nil {
		t.Fatalf("read goodbye stderr: %v", err)
	}
	if !strings.HasPrefix(string(stderr), "Device enrolled.") {
		t.Errorf("goodbye stderr = %q, want 'Device enrolled.' prefix", stderr)
	}
	if !strings.Contains(string(stderr), "Reconnect with your workspace connection") {
		t.Errorf("goodbye stderr missing reconnect instruction: %q", stderr)
	}

	// The channel closes after the goodbye so the client sees a complete
	// message rather than a hang.
	if _, err := ch.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("channel read after goodbye = %v, want EOF", err)
	}

	// The gateway closes the whole connection after the goodbye (§13.6).
	waitFor(t, 5*time.Second, func() bool {
		return client.Wait() != nil
	})

	// Enrollment actually persisted: the fresh key is linked to an account.
	if _, _, err := f.store.LookupByPublicKey(context.Background(), f.dep.ID, fresh.PublicKey()); err != nil {
		t.Fatalf("fresh key not linked by enrollment: %v", err)
	}
}
