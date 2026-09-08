package server_test

import (
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/config"
	"github.com/HamStudy/coder-ssh-gateway/internal/server"
	"github.com/HamStudy/coder-ssh-gateway/internal/sshauth"
)

// Keys-mode tests: an authenticated keymanagement connection serves exactly
// one session channel running the key-management UI, refuses every workspace
// channel type and forwarding request with a logged reason, and never
// constructs a workspace transport (zero coder child spawns).

const keysUser = "login-admin"

// armKeys arms the key-management username on the server's auth config,
// mirroring how the app layer will wire it (todo 8).
func armKeys(sc *server.ServerConfig) {
	sc.Auth.KeyManagementUser = keysUser
	sc.Auth.KeyManagement = &sshauth.KeyManagementEnabled{Enabled: true}
}

func transportCreates(f *gwFixture) int {
	f.transports.mu.Lock()
	defer f.transports.mu.Unlock()
	return f.transports.created
}

// assertZeroSpawns proves no keys-mode path constructed a workspace
// transport or started a coder child.
func assertZeroSpawns(t *testing.T, f *gwFixture) {
	t.Helper()
	if n := transportCreates(f); n != 0 {
		t.Errorf("workspace transports created = %d, want 0 on key management connections", n)
	}
	if n := f.starter.count(); n != 0 {
		t.Errorf("tunnel starter calls = %d, want 0 on key management connections", n)
	}
}

// collectExitStatuses drains the client-side request channel, reporting
// every exit-status value. The goroutine ends when the channel closes.
func collectExitStatuses(requests <-chan *ssh.Request) <-chan uint32 {
	out := make(chan uint32, 4)
	go func() {
		defer close(out)
		for req := range requests {
			if req == nil || req.Type != "exit-status" {
				continue
			}
			var s struct{ Status uint32 }
			if ssh.Unmarshal(req.Payload, &s) == nil {
				out <- s.Status
			}
		}
	}()
	return out
}

func waitExitStatus(t *testing.T, statuses <-chan uint32) uint32 {
	t.Helper()
	select {
	case st, ok := <-statuses:
		if !ok {
			t.Fatal("exit-status channel closed before a status arrived")
		}
		return st
	case <-time.After(5 * time.Second):
		t.Fatal("no exit-status received within 5s")
		return 0
	}
}

// ptyPayload marshals an RFC 4254 pty-req payload (tunnel.PtyRequest wire
// shape: term, cols, rows, width, height, modes).
func ptyPayload(term string, cols, rows uint32, modes string) []byte {
	return ssh.Marshal(&struct {
		Term          string
		Columns, Rows uint32
		Width, Height uint32
		Modes         string
	}{term, cols, rows, 0, 0, modes})
}

// Happy path: login-admin + the enrolled key authenticates with NO stored
// credential, the first session channel reaches the UI, the default
// enrollment user renders in the account-deletion hints, and quitting ends
// the channel cleanly with exit-status 0.
func TestKeyManagementUISessionServed(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	// Deliberately NO credential installed: keymanagement auth must not
	// consult the stored Coder token.

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		armKeys(sc)
	})
	defer ts.shutdown(t)

	client, err := dialGateway(ts.addr(), keysUser, ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("keys auth: %v", err)
	}
	defer client.Close()

	ch, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("session open: %v", err)
	}
	statuses := collectExitStatuses(requests)

	if ok, err := ch.SendRequest("shell", true, nil); err != nil || !ok {
		t.Fatalf("shell request: ok=%v err=%v, want accepted", ok, err)
	}

	// Account-deletion hints render the DEFAULT enrollment user (empty
	// server config falls back to "login").
	if _, err := ch.Write([]byte("d\n")); err != nil {
		t.Fatalf("write d: %v", err)
	}
	if _, err := ch.Write([]byte("x\n")); err != nil { // cancel the deletion
		t.Fatalf("write x: %v", err)
	}
	if _, err := ch.Write([]byte("q\n")); err != nil {
		t.Fatalf("write q: %v", err)
	}

	out, err := io.ReadAll(ch)
	if err != nil {
		t.Fatalf("read UI output: %v", err)
	}
	transcript := string(out)
	if !strings.Contains(transcript, "Coder SSH Gateway -- key management for taxilian") {
		t.Errorf("UI banner missing; transcript head: %q", head(transcript, 200))
	}
	if !strings.Contains(transcript, "with login@") {
		t.Errorf("default enrollment user hint missing (want login@): %q", head(transcript, 400))
	}
	if !strings.Contains(transcript, "Cancelled.") {
		t.Errorf("deletion cancel missing from transcript")
	}
	if !strings.Contains(transcript, "Bye.") {
		t.Errorf("quit goodbye missing from transcript")
	}

	if st := waitExitStatus(t, statuses); st != 0 {
		t.Errorf("exit-status = %d, want 0", st)
	}

	assertZeroSpawns(t, f)
}

// Full refusal matrix: every workspace channel type and forwarding global
// request is refused with the wire reason AND a log line; keepalive stays
// true; the inapplicable session requests are answered per policy.
func TestKeyManagementRefusalMatrix(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		armKeys(sc)
	})
	defer ts.shutdown(t)

	client, err := dialGateway(ts.addr(), keysUser, ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("keys auth: %v", err)
	}
	defer client.Close()

	ch, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("session open: %v", err)
	}
	statuses := collectExitStatuses(requests)

	t.Run("second session prohibited", func(t *testing.T) {
		_, _, err := client.OpenChannel("session", nil)
		reason, ok := openChannelReason(err)
		if !ok || reason != ssh.Prohibited {
			t.Errorf("second session err = %v, want Prohibited", err)
		}
	})

	t.Run("direct-tcpip prohibited", func(t *testing.T) {
		_, _, err := openDirectTCPIP(client, "dev", 22)
		reason, ok := openChannelReason(err)
		if !ok || reason != ssh.Prohibited {
			t.Errorf("direct-tcpip err = %v, want Prohibited", err)
		}
	})

	t.Run("forwarded-tcpip prohibited", func(t *testing.T) {
		_, _, err := client.OpenChannel("forwarded-tcpip", nil)
		reason, ok := openChannelReason(err)
		if !ok || reason != ssh.Prohibited {
			t.Errorf("forwarded-tcpip err = %v, want Prohibited", err)
		}
	})

	t.Run("x11 prohibited", func(t *testing.T) {
		_, _, err := client.OpenChannel("x11", nil)
		reason, ok := openChannelReason(err)
		if !ok || reason != ssh.Prohibited {
			t.Errorf("x11 err = %v, want Prohibited", err)
		}
	})

	t.Run("unknown channel type unsupported", func(t *testing.T) {
		_, _, err := client.OpenChannel("foo@bar", nil)
		reason, ok := openChannelReason(err)
		if !ok || reason != ssh.UnknownChannelType {
			t.Errorf("foo@bar err = %v, want UnknownChannelType", err)
		}
	})

	t.Run("tcpip-forward answered false", func(t *testing.T) {
		ok, _, err := client.SendRequest("tcpip-forward", true, nil)
		if err != nil {
			t.Fatalf("tcpip-forward: %v", err)
		}
		if ok {
			t.Error("tcpip-forward must be refused on key management connections")
		}
	})

	t.Run("cancel-tcpip-forward answered false", func(t *testing.T) {
		ok, _, err := client.SendRequest("cancel-tcpip-forward", true, nil)
		if err != nil {
			t.Fatalf("cancel-tcpip-forward: %v", err)
		}
		if ok {
			t.Error("cancel-tcpip-forward must be refused on key management connections")
		}
	})

	t.Run("keepalive answered true", func(t *testing.T) {
		ok, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		if err != nil {
			t.Fatalf("keepalive: %v", err)
		}
		if !ok {
			t.Error("keepalive@openssh.com must stay true")
		}
	})

	t.Run("inapplicable session requests", func(t *testing.T) {
		// subsystem: known type, deliberate policy refusal → false.
		if ok, err := ch.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"sftp"})); err != nil || ok {
			t.Errorf("subsystem: ok=%v err=%v, want refused", ok, err)
		}
		// env is accepted and discarded.
		if ok, err := ch.SendRequest("env", true, ssh.Marshal(struct{ Name, Value string }{"LANG", "C"})); err != nil || !ok {
			t.Errorf("env: ok=%v err=%v, want accepted-and-discarded", ok, err)
		}
		// window-change and signal are answered true as documented no-ops.
		if ok, err := ch.SendRequest("window-change", true, ssh.Marshal(struct{ Columns, Rows, Width, Height uint32 }{100, 40, 0, 0})); err != nil || !ok {
			t.Errorf("window-change: ok=%v err=%v, want true no-op", ok, err)
		}
		if ok, err := ch.SendRequest("signal", true, ssh.Marshal(struct{ Signal string }{"TERM"})); err != nil || !ok {
			t.Errorf("signal: ok=%v err=%v, want true no-op", ok, err)
		}
		// agent forwarding has no inner session to mirror → refused.
		if ok, err := ch.SendRequest("auth-agent-req@openssh.com", true, nil); err != nil || ok {
			t.Errorf("auth-agent-req: ok=%v err=%v, want refused", ok, err)
		}
	})

	t.Run("exec refused with message and exit-status 1", func(t *testing.T) {
		if ok, err := ch.SendRequest("exec", true, ssh.Marshal(struct{ Command string }{"ls"})); err != nil || ok {
			t.Fatalf("exec: ok=%v err=%v, want refused", ok, err)
		}
		stderr, err := io.ReadAll(ch.Stderr())
		if err != nil {
			t.Fatalf("read exec stderr: %v", err)
		}
		if string(stderr) != "exec is not available on key management connections\r\n" {
			t.Errorf("exec stderr = %q, want refusal message", stderr)
		}
		if st := waitExitStatus(t, statuses); st != 1 {
			t.Errorf("exec exit-status = %d, want 1", st)
		}
	})

	t.Run("session still one per connection after exec", func(t *testing.T) {
		_, _, err := client.OpenChannel("session", nil)
		reason, ok := openChannelReason(err)
		if !ok || reason != ssh.Prohibited {
			t.Errorf("post-exec session err = %v, want Prohibited", err)
		}
	})

	// Never-silent: every refusal above must be visible in the log buffer.
	for _, want := range []string{
		"key management channel rejected channel_type=session",
		"key management channel rejected channel_type=direct-tcpip",
		"key management channel rejected channel_type=forwarded-tcpip",
		"key management channel rejected channel_type=x11",
		"key management connections cannot open workspace channels",
		"rejecting unsupported channel type channel_type=foo@bar",
		"key management global request rejected request_type=tcpip-forward",
		"no workspace transport on key management connections",
		"key management session request refused request_type=subsystem",
		"key management session request refused request_type=auth-agent-req@openssh.com",
		"exec refused on key-management connection",
	} {
		if !f.logs.contains(want) {
			t.Errorf("log line missing: %q", want)
		}
	}

	assertZeroSpawns(t, f)
}

// A pty session reaches the UI with pty line-editing enabled (backspace
// erase echo proves the pty flag was wired through), and a malformed
// pty-req is refused without killing the session.
func TestKeyManagementPtySession(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		armKeys(sc)
	})
	defer ts.shutdown(t)

	t.Run("malformed pty-req refused", func(t *testing.T) {
		client, err := dialGateway(ts.addr(), keysUser, ssh.PublicKeys(f.signer))
		if err != nil {
			t.Fatalf("keys auth: %v", err)
		}
		defer client.Close()
		ch, requests, err := client.OpenChannel("session", nil)
		if err != nil {
			t.Fatalf("session open: %v", err)
		}
		statuses := collectExitStatuses(requests)

		// Truncated payload: string header claims 9 bytes, 1 follows.
		if ok, err := ch.SendRequest("pty-req", true, []byte{0, 0, 0, 9, 'x'}); err != nil || ok {
			t.Errorf("garbage pty-req: ok=%v err=%v, want refused", ok, err)
		}
		// Row count out of range.
		if ok, err := ch.SendRequest("pty-req", true, ptyPayload("xterm", 80, 1<<31, "\x00")); err != nil || ok {
			t.Errorf("oversized-dims pty-req: ok=%v err=%v, want refused", ok, err)
		}
		waitFor(t, 3*time.Second, func() bool {
			return f.logs.contains("key management pty-req rejected")
		})

		// The session still works without a pty.
		if ok, err := ch.SendRequest("shell", true, nil); err != nil || !ok {
			t.Fatalf("shell after refused pty: ok=%v err=%v", ok, err)
		}
		// A second shell on the started session is refused without
		// disturbing the running UI.
		if ok, err := ch.SendRequest("shell", true, nil); err != nil || ok {
			t.Errorf("duplicate shell: ok=%v err=%v, want refused", ok, err)
		}
		if _, err := ch.Write([]byte("q\n")); err != nil {
			t.Fatalf("write q: %v", err)
		}
		out, err := io.ReadAll(ch)
		if err != nil {
			t.Fatalf("read UI output: %v", err)
		}
		if !strings.Contains(string(out), "Bye.") {
			t.Errorf("no-pty session did not reach the UI: %q", head(string(out), 200))
		}
		if st := waitExitStatus(t, statuses); st != 0 {
			t.Errorf("exit-status = %d, want 0", st)
		}
	})

	t.Run("pty session with backspace erase", func(t *testing.T) {
		client, err := dialGateway(ts.addr(), keysUser, ssh.PublicKeys(f.signer))
		if err != nil {
			t.Fatalf("keys auth: %v", err)
		}
		defer client.Close()
		ch, requests, err := client.OpenChannel("session", nil)
		if err != nil {
			t.Fatalf("session open: %v", err)
		}
		statuses := collectExitStatuses(requests)

		if ok, err := ch.SendRequest("pty-req", true, ptyPayload("xterm", 80, 24, "\x00")); err != nil || !ok {
			t.Fatalf("pty-req: ok=%v err=%v, want accepted", ok, err)
		}
		if ok, err := ch.SendRequest("shell", true, nil); err != nil || !ok {
			t.Fatalf("shell: ok=%v err=%v, want accepted", ok, err)
		}

		// Type "z", erase it (pty echo of "\b \b"), Enter: empty line →
		// Invalid input. The erase echo only happens when the pty flag
		// reached the UI service. The quit line ends CRLF: the line
		// reader blocks in Peek after a bare CR (keymgmt CRLF collapse),
		// so a trailing CR alone would stall the transcript.
		if _, err := ch.Write([]byte("z\x7f\r")); err != nil {
			t.Fatalf("write z+backspace: %v", err)
		}
		if _, err := ch.Write([]byte("q\r\n")); err != nil {
			t.Fatalf("write q: %v", err)
		}
		out, err := io.ReadAll(ch)
		if err != nil {
			t.Fatalf("read UI output: %v", err)
		}
		transcript := string(out)
		if !strings.Contains(transcript, "Coder SSH Gateway -- key management for taxilian") {
			t.Errorf("UI banner missing: %q", head(transcript, 200))
		}
		if !strings.Contains(transcript, "\b \b") {
			t.Errorf("pty backspace erase echo missing (pty flag not wired): %q", head(transcript, 300))
		}
		if !strings.Contains(transcript, "Invalid input.") {
			t.Errorf("erased empty line must yield Invalid input.: %q", head(transcript, 300))
		}
		if st := waitExitStatus(t, statuses); st != 0 {
			t.Errorf("exit-status = %d, want 0", st)
		}
	})

	assertZeroSpawns(t, f)
}

// The server's EnrollmentUser config field renders in the recovery hints;
// empty means keymgmt's "login" fallback (covered by the happy path).
func TestKeyManagementEnrollmentUserConfigured(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		armKeys(sc)
		sc.EnrollmentUser = "signin"
	})
	defer ts.shutdown(t)

	client, err := dialGateway(ts.addr(), keysUser, ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("keys auth: %v", err)
	}
	defer client.Close()

	ch, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("session open: %v", err)
	}
	statuses := collectExitStatuses(requests)

	if ok, err := ch.SendRequest("shell", true, nil); err != nil || !ok {
		t.Fatalf("shell: ok=%v err=%v", ok, err)
	}
	if _, err := ch.Write([]byte("d\n")); err != nil {
		t.Fatalf("write d: %v", err)
	}
	if _, err := ch.Write([]byte("x\n")); err != nil {
		t.Fatalf("write x: %v", err)
	}
	if _, err := ch.Write([]byte("q\n")); err != nil {
		t.Fatalf("write q: %v", err)
	}

	out, err := io.ReadAll(ch)
	if err != nil {
		t.Fatalf("read UI output: %v", err)
	}
	if !strings.Contains(string(out), "with signin@") {
		t.Errorf("configured enrollment user missing (want signin@): %q", head(string(out), 400))
	}
	if st := waitExitStatus(t, statuses); st != 0 {
		t.Errorf("exit-status = %d, want 0", st)
	}
	assertZeroSpawns(t, f)
}

// A client disappearing mid-UI tears down cleanly: the per-key/per-account
// connection slots are released and no goroutines survive (goleak).
func TestKeyManagementClientDisconnectMidUI(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		armKeys(sc)
	})
	defer ts.shutdown(t)

	client, err := dialGateway(ts.addr(), keysUser, ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("keys auth: %v", err)
	}
	defer client.Close()

	ch, _, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("session open: %v", err)
	}
	if ok, err := ch.SendRequest("shell", true, nil); err != nil || !ok {
		t.Fatalf("shell: ok=%v err=%v", ok, err)
	}

	// Wait until the UI is actually serving (banner bytes arrived), then
	// disappear without quitting.
	banner := make([]byte, 32)
	if _, err := io.ReadAtLeast(ch, banner, len(banner)); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	_ = client.Close()

	waitFor(t, 5*time.Second, func() bool {
		u := ts.counters.Usage()
		return len(u.Keys) == 0 && len(u.Accounts) == 0
	})
	assertZeroSpawns(t, f)
}

// head returns the first n bytes of s for failure messages.
func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
