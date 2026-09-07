package tunnel

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// stubPendingTransport records the replay it receives, then returns.
type stubPendingTransport struct {
	mu     sync.Mutex
	queued []QueuedSessionRequest
}

func (s *stubPendingTransport) BridgeSession(ctx context.Context, channel ssh.Channel, requests <-chan *ssh.Request, queued []QueuedSessionRequest) error {
	s.mu.Lock()
	s.queued = append(s.queued, queued...)
	s.mu.Unlock()
	return nil
}

func (s *stubPendingTransport) ReplayCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queued)
}

func (s *stubPendingTransport) RelayChannel(newCh ssh.NewChannel) {}

func (s *stubPendingTransport) RelayGlobalRequest(reqType string, wantReply bool, payload []byte) (bool, []byte) {
	return true, nil
}

func (s *stubPendingTransport) Close() {}

// BridgePendingSession must acknowledge pre-transport session requests the
// same way the live bridge will (§19.9), queue the start-bearing ones, and
// replay them to the transport when it arrives.

func TestBridgePendingSessionQueuesRequestsAndReplays(t *testing.T) {
	tr := &stubPendingTransport{}
	ch, _, _ := newFakeChannel(t)
	requests := make(chan *ssh.Request)
	pending := make(chan PendingTransport)
	feedDone := make(chan struct{})
	go func() {
		defer close(feedDone)
		// Rendezvous sends force the consumption order: both requests queue
		// before the transport is delivered.
		requests <- &ssh.Request{Type: "pty-req", WantReply: false, Payload: ssh.Marshal(ptyRequest{Term: "xterm", Columns: 80, Rows: 24, Modes: "\x00"})}
		requests <- &ssh.Request{Type: "shell", WantReply: false}
		pending <- PendingTransport{Tr: tr}
	}()

	err := BridgePendingSession(context.Background(), ch, requests, pending, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	<-feedDone
	if got := tr.ReplayCount(); got != 2 {
		t.Fatalf("replayed requests = %d, want 2 (pty-req + shell)", got)
	}
}

func TestBridgePendingSessionReturnsTransportFailure(t *testing.T) {
	ch, _, _ := newFakeChannel(t)
	requests := make(chan *ssh.Request)
	pending := make(chan PendingTransport, 1)
	pending <- PendingTransport{Err: errors.New("coder process failed")}

	err := BridgePendingSession(context.Background(), ch, requests, pending, slog.New(slog.DiscardHandler))
	if err == nil || err.Error() != "coder process failed" {
		t.Fatalf("bridge error = %v, want transport failure", err)
	}
}

func TestBridgePendingSessionClientClosedBeforeTransport(t *testing.T) {
	ch, _, _ := newFakeChannel(t)
	requests := make(chan *ssh.Request)
	close(requests)
	pending := make(chan PendingTransport)

	err := BridgePendingSession(context.Background(), ch, requests, pending, slog.New(slog.DiscardHandler))
	if err == nil || err.Error() != "outer session closed before workspace transport ready" {
		t.Fatalf("bridge error = %v, want client-closed-first error", err)
	}
}

// syncBuffer is a goroutine-safe sink for captured slog output.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// §19.9 regression guard: a request that fails validation must produce an
// operator-visible rejection (WARN) carrying the reason — the silent pty-req
// refusal is what hid the Termius incompatibility for a full debugging day.
func TestBridgePendingSessionRejectionsAreVisible(t *testing.T) {
	tr := &stubPendingTransport{}
	ch, _, _ := newFakeChannel(t)
	sink := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(sink, nil))
	requests := make(chan *ssh.Request)
	pending := make(chan PendingTransport)
	feedDone := make(chan struct{})
	go func() {
		defer close(feedDone)
		requests <- &ssh.Request{Type: "pty-req", WantReply: false, Payload: ssh.Marshal(ptyRequest{Term: "xterm", Columns: 80, Rows: 24, Modes: "\x01\x02"})}
		pending <- PendingTransport{Tr: tr}
	}()

	err := BridgePendingSession(context.Background(), ch, requests, pending, log)
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	<-feedDone

	logs := sink.String()
	if !strings.Contains(logs, "session request rejected pre-transport") {
		t.Errorf("rejected request not logged; logs = %q", logs)
	}
	if !strings.Contains(logs, "invalid pty-req") {
		t.Errorf("rejection reason not logged; logs = %q", logs)
	}
}

func TestQueueDecisionMatchesLiveBridgeContract(t *testing.T) {
	cases := []struct {
		name      string
		typ       string
		payload   []byte
		queueable bool
		valid     bool
	}{
		{"env valid", "env", ssh.Marshal(envRequest{Name: "LANG", Value: "en_US.UTF-8"}), true, true},
		{"env empty name", "env", ssh.Marshal(envRequest{Name: "", Value: "x"}), false, false},
		{"agent req", "auth-agent-req@openssh.com", nil, true, true},
		{"pty valid", "pty-req", ssh.Marshal(ptyRequest{Term: "xterm", Columns: 80, Rows: 24, Modes: "\x00"}), true, true},
		{"pty empty term", "pty-req", ssh.Marshal(ptyRequest{Term: "", Columns: 80, Rows: 24, Modes: "\x00"}), true, true},
		{"pty empty modes", "pty-req", ssh.Marshal(ptyRequest{Term: "xterm", Columns: 80, Rows: 24}), true, true},
		{"pty truncated modes", "pty-req", ssh.Marshal(ptyRequest{Term: "xterm", Columns: 80, Rows: 24, Modes: "\x01\x02"}), false, false},
		{"pty bad dims", "pty-req", ssh.Marshal(ptyRequest{Term: "xterm", Columns: 0, Rows: 1 << 31, Modes: "\x00"}), false, false},
		{"shell empty payload", "shell", nil, true, true},
		{"shell with payload", "shell", []byte{1}, false, false},
		{"exec valid", "exec", ssh.Marshal(execRequest{Command: "true"}), true, true},
		{"exec empty command", "exec", ssh.Marshal(execRequest{Command: ""}), false, false},
		{"subsystem valid", "subsystem", ssh.Marshal(subsystemRequest{Name: "sftp"}), true, true},
		{"unknown type", "flurb", nil, false, false},
		{"window-change pre-start", "window-change", ssh.Marshal(windowChangeRequest{Columns: 80, Rows: 24}), false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			queueable, valid, reason := queueDecision(tc.typ, tc.payload)
			if queueable != tc.queueable || valid != tc.valid {
				t.Errorf("queueDecision(%q) = (%v, %v, %q), want (%v, %v)",
					tc.typ, queueable, valid, reason, tc.queueable, tc.valid)
			}
			if !valid && reason == "" {
				t.Errorf("queueDecision(%q) refused without a reason; rejections are never silent", tc.typ)
			}
		})
	}
}
