package server_test

import (
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/config"
	"github.com/HamStudy/coder-ssh-gateway/internal/server"
)

// §8.4: keepalive@openssh.com is answered true; tcpip-forward and
// cancel-tcpip-forward relay to the workspace transport (the fake answers
// true); arbitrary vendor requests are answered false. The requests channel
// must be drained so WantReply callers never block.
func TestGlobalRequestPolicy(t *testing.T) {
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

	ok, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
	if err != nil {
		t.Fatalf("keepalive request: %v", err)
	}
	if !ok {
		t.Error("keepalive@openssh.com must be answered true (§8.4)")
	}

	ok, _, err = client.SendRequest("tcpip-forward", true, nil)
	if err != nil {
		t.Fatalf("tcpip-forward: %v", err)
	}
	if !ok {
		t.Error("tcpip-forward must relay to the transport")
	}
	ok, _, err = client.SendRequest("cancel-tcpip-forward", true, nil)
	if err != nil {
		t.Fatalf("cancel-tcpip-forward: %v", err)
	}
	if !ok {
		t.Error("cancel-tcpip-forward must relay or succeed idempotently")
	}
	waitFor(t, 5*time.Second, func() bool {
		_, globals := f.transports.tr.counts()
		return globals >= 1
	})

	for _, reqType := range []string{
		"streamlocal-forward@openssh.com",
		"vendor-undefined@example.com",
	} {
		ok, _, err := client.SendRequest(reqType, true, nil)
		if err != nil {
			t.Fatalf("%s: WantReply caller blocked or errored (drain broken, §19.10): %v", reqType, err)
		}
		if ok {
			t.Errorf("%s must be answered false (§8.4)", reqType)
		}
	}
}

// Without a transport factory, tcpip-forward is answered false: no factory,
// no relay.
func TestGlobalRequestWithoutFactoryRejected(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		sc.WorkspaceTransports = nil
	})
	defer ts.shutdown(t)

	client, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	defer client.Close()

	ok, _, err := client.SendRequest("tcpip-forward", true, nil)
	if err != nil {
		t.Fatalf("tcpip-forward: %v", err)
	}
	if ok {
		t.Error("tcpip-forward without a factory must be answered false")
	}
}

// A tcpip-forward request carrying a realistic payload still relays —
// payload content is never consulted and never logged (§34.1).
func TestReverseForwardWithPayloadRelayed(t *testing.T) {
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

	// RFC 4254 §7.1 tcpip-forward payload: string address, uint32 port.
	payload := ssh.Marshal(struct {
		Address string
		Port    uint32
	}{"127.0.0.1", 19999})
	ok, _, err := client.SendRequest("tcpip-forward", true, payload)
	if err != nil {
		t.Fatalf("tcpip-forward: %v", err)
	}
	if !ok {
		t.Error("payload-carrying tcpip-forward must relay")
	}
	waitFor(t, 5*time.Second, func() bool {
		_, globals := f.transports.tr.counts()
		return globals >= 1
	})
}
