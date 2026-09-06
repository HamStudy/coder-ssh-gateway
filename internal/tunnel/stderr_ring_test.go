package tunnel

import (
	"strings"
	"testing"

	"github.com/HamStudy/coder-ssh-gateway/internal/testleaks"
)

// §19.7: the ring keeps the tail and never grows past the cap.
func TestStderrRingTailBound(t *testing.T) {
	defer testleaks.Verify(t)

	r := NewStderrRing(16)
	if _, err := r.Write([]byte("0123456789abcdef")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := string(r.Tail()); got != "0123456789abcdef" {
		t.Fatalf("Tail = %q, want full 16 bytes", got)
	}
	if _, err := r.Write([]byte("XYZ")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := string(r.Tail()); got != "3456789abcdefXYZ" {
		t.Fatalf("Tail = %q, want last 16 bytes %q", got, "3456789abcdefXYZ")
	}
}

func TestStderrRingDefaultBound(t *testing.T) {
	defer testleaks.Verify(t)

	r := NewStderrRing(0)
	big := strings.Repeat("y", 100*1024)
	if _, err := r.Write([]byte(big)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	tail := r.Tail()
	if len(tail) != DefaultStderrRingBytes {
		t.Fatalf("Tail length = %d, want default cap %d", len(tail), DefaultStderrRingBytes)
	}
	if string(tail[:16]) != strings.Repeat("y", 16) {
		t.Error("Tail content corrupted")
	}
}

// §19.7: credential-like material (>=20 char runs joined by separators) is
// defensively redacted before storage.
func TestStderrRingRedaction(t *testing.T) {
	defer testleaks.Verify(t)

	tok := "abcdef1234567890-abcdefghij1234567890"
	r := NewStderrRing(0)
	if _, err := r.Write([]byte("auth failed: token " + tok + " rejected by server")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	tail := string(r.Tail())
	if strings.Contains(tail, tok) {
		t.Errorf("Tail contains token material: %q", tail)
	}
	if !strings.Contains(tail, "[REDACTED]") {
		t.Errorf("Tail = %q, want it to contain [REDACTED]", tail)
	}
	if !strings.Contains(tail, "auth failed: token") {
		t.Errorf("Tail = %q, want surrounding diagnostic text preserved", tail)
	}
}

// A token split across two Write calls is still redacted once complete.
func TestStderrRingRedactionAcrossWrites(t *testing.T) {
	defer testleaks.Verify(t)

	r := NewStderrRing(0)
	_, _ = r.Write([]byte("prefix abcdef1234567890"))
	_, _ = r.Write([]byte("-abcdefghij1234567890 suffix"))
	tail := string(r.Tail())
	if strings.Contains(tail, "abcdef1234567890-abcdefghij1234567890") {
		t.Errorf("Tail contains token material spanning writes: %q", tail)
	}
	if !strings.Contains(tail, "[REDACTED]") {
		t.Errorf("Tail = %q, want [REDACTED]", tail)
	}
}

// Tail returns a defensive copy: mutating it must not corrupt the ring.
func TestStderrRingTailCopy(t *testing.T) {
	defer testleaks.Verify(t)

	r := NewStderrRing(64)
	_, _ = r.Write([]byte("hello"))
	tail := r.Tail()
	tail[0] = 'X'
	if got := string(r.Tail()); got != "hello" {
		t.Errorf("Tail = %q after caller mutation, want %q", got, "hello")
	}
}

// Short, separator-free diagnostic text must pass through untouched.
func TestStderrRingKeepsPlainText(t *testing.T) {
	defer testleaks.Verify(t)

	r := NewStderrRing(0)
	msg := "coder: workspace agent not ready yet"
	_, _ = r.Write([]byte(msg))
	if got := string(r.Tail()); got != msg {
		t.Errorf("Tail = %q, want %q (plain diagnostics must not be redacted)", got, msg)
	}
}
