package server_test

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/config"
	"github.com/taxilian/coder-ssh-gateway/internal/server"
	"github.com/taxilian/coder-ssh-gateway/internal/sshauth"
)

// A panicking per-connection code path (here the injected pre-auth gate)
// must be contained: the connection dies, the server keeps serving.
func TestPanicInHandlerContained(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	var calls atomic.Int32
	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		sc.PreAuthGate = func(ip string) bool {
			if calls.Add(1) == 1 {
				panic("injected gate panic")
			}
			return true
		}
	})
	defer ts.shutdown(t)

	first, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if first != nil {
		first.Close()
	}
	if err == nil {
		t.Fatal("first connection should have died with the injected panic")
	}

	second, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("server must survive a handler panic: %v", err)
	}
	second.Close()
}

// N+1th unauthenticated connection over the global limit is closed
// immediately (§20 unauthenticated TCP connections, global).
func TestAdmissionGlobalUnauthLimit(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		sc.HandshakeTimeout = 5 * time.Second
		lc.Limits.UnauthenticatedConnections = 1
	})
	defer ts.shutdown(t)

	held := dialRaw(t, ts.addr()) // occupies the single unauth slot
	defer held.Close()

	start := time.Now()
	over := dialRaw(t, ts.addr())
	defer over.Close()
	_ = over.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := over.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection over the global unauth limit must be closed immediately")
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("over-limit close took %v, want immediate", time.Since(start))
	}
}

// Per-IP limit is held for the connection lifetime: conn1 authenticated,
// conn2 from the same address is refused until conn1 closes.
func TestAdmissionPerIPLimit(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		lc.Limits.ConnectionsPerIP = 1
	})
	defer ts.shutdown(t)

	first, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("first auth: %v", err)
	}

	second, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if second != nil {
		second.Close()
	}
	if err == nil {
		t.Fatal("second connection from the same IP must be refused at the per-IP limit")
	}

	first.Close()

	// Release happens in the server handler's defer; poll for capacity.
	deadline := time.Now().Add(3 * time.Second)
	for {
		third, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
		if err == nil {
			third.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("per-IP slot never released after first conn closed: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The pre-auth rate gate refuses the connection before any SSH bytes.
func TestPreAuthGateRefusal(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		sc.PreAuthGate = func(ip string) bool { return false }
	})
	defer ts.shutdown(t)

	client, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if client != nil {
		client.Close()
	}
	if err == nil {
		t.Fatal("gate-refused connection must not complete a handshake")
	}
}

// Startup logs the SHA256 host-key fingerprints (§30.1: fingerprint is
// published through a trusted channel — the startup log is that channel).
func TestStartupLogsHostKeyFingerprint(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)

	ts := startTestServer(t, f, nil)
	defer ts.shutdown(t)

	if !f.logs.contains("SHA256:") {
		t.Error("startup log must include host key SHA256 fingerprints")
	}
}

// PROXY protocol enabled + valid v1 header: the asserted peer replaces the
// socket peer in ConnState and lands in the audit record (§31.4 retain both
// real and asserted — the asserted address is what audit sees).
func TestProxyProtocolEnabledValidHeader(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		sc.ProxyProtocol = true
	})
	defer ts.shutdown(t)

	raw := dialRaw(t, ts.addr())
	defer raw.Close()
	if _, err := raw.Write([]byte("PROXY TCP4 203.0.113.7 192.0.2.10 41234 2222\r\n")); err != nil {
		t.Fatalf("write PROXY header: %v", err)
	}

	conn, chans, reqs, err := ssh.NewClientConn(raw, ts.addr(), &ssh.ClientConfig{
		User:            "coder",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(f.signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("handshake over PROXY conn: %v", err)
	}
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()

	waitFor(t, 3*time.Second, func() bool {
		return len(f.auditEvents(sshauth.EventTypeKeyVerified)) >= 1
	})
	ev := f.auditEvents(sshauth.EventTypeKeyVerified)[0]
	if ev.PeerAddress != "203.0.113.7:41234" {
		t.Errorf("audit peer = %q, want asserted PROXY peer 203.0.113.7:41234", ev.PeerAddress)
	}
}

// PROXY protocol disabled: the header bytes are NOT honored. x/crypto (per
// RFC 4253) tolerates non-"SSH-" preamble lines before the client version,
// so the handshake still completes — the assertion that matters is that the
// asserted address never lands in audit/ConnState (no auto-detect, §31.4).
func TestProxyProtocolDisabledHeaderIgnored(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, nil) // ProxyProtocol defaults off
	defer ts.shutdown(t)

	raw := dialRaw(t, ts.addr())
	defer raw.Close()
	if _, err := raw.Write([]byte("PROXY TCP4 203.0.113.7 192.0.2.10 41234 2222\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn, chans, reqs, err := ssh.NewClientConn(raw, ts.addr(), &ssh.ClientConfig{
		User:            "coder",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(f.signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()

	waitFor(t, 3*time.Second, func() bool {
		return len(f.auditEvents(sshauth.EventTypeKeyVerified)) >= 1
	})
	ev := f.auditEvents(sshauth.EventTypeKeyVerified)[0]
	if strings.Contains(ev.PeerAddress, "203.0.113.7") {
		t.Errorf("PROXY-asserted address must be ignored when disabled, got peer %q", ev.PeerAddress)
	}
	if !strings.HasPrefix(ev.PeerAddress, "127.0.0.1:") {
		t.Errorf("audit peer = %q, want real socket peer 127.0.0.1:*", ev.PeerAddress)
	}
}

// PROXY protocol enabled but the peer speaks SSH directly: strict parse
// fails fast and closes (no auto-detection fallback, §31.4).
func TestProxyProtocolEnabledGarbageHeader(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		sc.ProxyProtocol = true
	})
	defer ts.shutdown(t)

	raw := dialRaw(t, ts.addr())
	defer raw.Close()
	if _, err := raw.Write([]byte("SSH-2.0-OpenSSH_9.9\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := raw.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection without a valid PROXY header must be closed when the option is enabled")
	}
}

// Cancelling the server context closes the listener AND active connections,
// and Serve returns nil promptly (graceful stop; draining is T24).
func TestGracefulShutdownClosesActiveConn(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, nil)

	client, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	defer client.Close()

	// Wait() unblocks when the server-side shutdown kills the transport.
	// (SendRequest is unusable here: x/crypto v0.52.0's drain loop spins
	// forever on the closed globalResponses channel once the mux is dead.)
	waitErr := make(chan error, 1)
	go func() { waitErr <- client.Conn.Wait() }()

	ts.shutdown(t) // cancels ctx, asserts Serve returned nil

	select {
	case <-waitErr:
	case <-time.After(3 * time.Second):
		t.Fatal("client connection still alive after server shutdown")
	}
}

func TestNewRequiresHostSignersAndCounters(t *testing.T) {
	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)

	if _, err := server.New(server.ServerConfig{Auth: f.authConfig()}); err == nil {
		t.Fatal("New without host signers must fail (§30.1)")
	}
	if _, err := server.New(server.ServerConfig{
		HostSigners: []ssh.Signer{hostSigner(t)},
		Auth:        f.authConfig(),
	}); err == nil {
		t.Fatal("New without counters must fail closed")
	}
}

// The configured ServerVersion lands on the wire (§25.1).
func TestServerVersionOnWire(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-transport-0123456789")

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		sc.ServerVersion = "SSH-2.0-CoderSSHGW_Test"
	})
	defer ts.shutdown(t)

	raw := dialRaw(t, ts.addr())
	defer raw.Close()
	_ = raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := raw.Read(buf)
	if err != nil {
		t.Fatalf("read version banner: %v", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "SSH-2.0-CoderSSHGW_Test") {
		t.Errorf("server banner = %q, want configured version", string(buf[:n]))
	}
}
