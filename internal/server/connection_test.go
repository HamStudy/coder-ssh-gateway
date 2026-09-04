package server_test

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/config"
	"github.com/taxilian/coder-ssh-gateway/internal/server"
	"github.com/taxilian/coder-ssh-gateway/internal/sshauth"
)

// Full pubkey auth succeeds through the real listener, and the post-auth
// connection survives past the (short) handshake deadline — proving the
// deadline is cleared after a successful handshake (§13.5).
func TestHandshakeSuccessDeadlineCleared(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		sc.HandshakeTimeout = 400 * time.Millisecond
	})
	defer ts.shutdown(t)

	client, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("transport auth failed: %v", err)
	}
	defer client.Close()

	time.Sleep(700 * time.Millisecond) // beyond the 400ms handshake deadline

	ok, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
	if err != nil {
		t.Fatalf("keepalive after deadline window failed (deadline not cleared?): %v", err)
	}
	if !ok {
		t.Error("keepalive@openssh.com must be answered true (§8.4)")
	}
}

// A client that never sends its SSH version banner must be torn down by the
// handshake deadline (§13.5 initial phase).
func TestSlowHandshakeTornDown(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		sc.HandshakeTimeout = 300 * time.Millisecond
	})
	defer ts.shutdown(t)

	conn := dialRaw(t, ts.addr())
	defer conn.Close()

	// The server sends its version banner immediately; consume it, then the
	// next read must fail once the handshake deadline tears the conn down.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("expected server version banner, got error: %v", err)
	}

	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Read(buf)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("silent connection must be closed by the handshake deadline")
	}
	if elapsed > 3*time.Second {
		t.Errorf("teardown took %v, want ~300ms deadline + slack", elapsed)
	}
	if elapsed < 200*time.Millisecond {
		t.Errorf("teardown after %v — deadline fired suspiciously early", elapsed)
	}
}

// Unknown key: client sees a generic publickey failure (§35), server audits
// the handshake failure. Outward message must not distinguish causes.
func TestUnknownKeyRejected(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, nil)
	defer ts.shutdown(t)

	unknown := newClientSigner(t)
	client, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(unknown))
	if client != nil {
		client.Close()
	}
	if err == nil {
		t.Fatal("expected auth failure for unknown key")
	}
	if !strings.Contains(err.Error(), "unable to authenticate") {
		t.Errorf("client error = %q, want generic publickey failure", err)
	}

	waitFor(t, 3*time.Second, func() bool {
		return len(f.auditEvents(server.EventTypeHandshakeFailed)) >= 1
	})
}

// Two concurrent handshakes against the same Server exercise the per-conn
// shallow-copy rule (§9.4): under -race, any mutation of the shared base
// config's slices/maps would be caught here.
func TestConcurrentHandshakesBaseConfigImmutable(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, nil)
	defer ts.shutdown(t)

	const workers = 4
	const authsPerWorker = 2

	var wg sync.WaitGroup
	errs := make(chan error, workers*authsPerWorker)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < authsPerWorker; i++ {
				client, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
				if err != nil {
					errs <- err
					continue
				}
				ok, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				if err != nil || !ok {
					errs <- errors.New("keepalive failed after concurrent auth")
				}
				client.Close()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent handshake: %v", err)
	}
}

// Maintenance user authenticates with no credential at all (§14.1) and gets
// maintenance permissions; channels are still placeholder-rejected in T15.
func TestMaintenanceModeAuth(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)

	ts := startTestServer(t, f, nil)
	defer ts.shutdown(t)

	client, err := dialGateway(ts.addr(), "auth", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("maintenance auth failed: %v", err)
	}
	defer client.Close()

	verified := f.auditEvents(sshauth.EventTypeKeyVerified)
	if len(verified) != 1 {
		t.Errorf("verified events = %d, want 1", len(verified))
	}
}

// Session channel on a transport connection: the T15 placeholder rejects ALL
// channel types with Prohibited (T16 refines to the §8.3/§8.5 matrix).
func TestSessionChannelRejectedPlaceholder(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, nil)
	defer ts.shutdown(t)

	client, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	defer client.Close()

	_, _, err = client.OpenChannel("session", nil)
	if err == nil {
		t.Fatal("session channel must be rejected by the placeholder")
	}
	var openErr *ssh.OpenChannelError
	if !errors.As(err, &openErr) {
		t.Fatalf("error %T = %v, want *ssh.OpenChannelError", err, err)
	}
	if openErr.Reason != ssh.Prohibited {
		t.Errorf("rejection reason = %v, want Prohibited", openErr.Reason)
	}
}
