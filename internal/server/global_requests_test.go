package server_test

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

// §8.4: keepalive@openssh.com is answered true; tcpip-forward,
// cancel-tcpip-forward, and arbitrary vendor requests are answered false.
// The requests channel must be drained so WantReply callers never block.
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

	for _, reqType := range []string{
		"tcpip-forward",
		"cancel-tcpip-forward",
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

	if !f.logs.contains("reverse forwarding rejected") {
		t.Error("tcpip-forward rejection must be logged at debug (§8.4)")
	}
}

// A tcpip-forward request carrying a realistic payload is still rejected
// false — payload content is never consulted (and never logged, §34.1).
func TestReverseForwardWithPayloadRejected(t *testing.T) {
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
	}{"0.0.0.0", 9999})

	ok, _, err := client.SendRequest("tcpip-forward", true, payload)
	if err != nil {
		t.Fatalf("tcpip-forward with payload: %v", err)
	}
	if ok {
		t.Error("tcpip-forward must be answered false even with a valid payload")
	}
	t.Log("EVIDENCE: tcpip-forward (0.0.0.0:9999) rejected false at wire level")
}
