package sshauth

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestConnStateBasics(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	s1 := NewConnState(a)
	s2 := NewConnState(b)
	if s1.ID() == "" || s2.ID() == "" {
		t.Fatal("connection IDs must be generated pre-handshake (§34.4)")
	}
	if s1.ID() == s2.ID() {
		t.Fatal("connection IDs must be unique")
	}
	if s1.PeerAddr() == "" {
		t.Error("PeerAddr empty for net.Pipe")
	}
	if s1.RawConn() != a {
		t.Error("RawConn mismatch")
	}

	// SendBanner is a no-op without a pre-auth conn and must not panic.
	s1.SendBanner("hello")

	// SetDeadline passes through to the raw conn (§13.5).
	deadline := time.Now().Add(time.Minute)
	if err := s1.SetDeadline(deadline); err != nil {
		t.Errorf("SetDeadline: %v", err)
	}

	if _, _, _, ok := s1.VerifiedIdentity(); ok {
		t.Error("VerifiedIdentity before proof of possession")
	}
	if got := s1.RenewalAttempts(); got != 0 {
		t.Errorf("RenewalAttempts = %d", got)
	}
	if got := s1.IncrementRenewalAttempts(); got != 1 {
		t.Errorf("IncrementRenewalAttempts = %d", got)
	}
	if s1.MustReconnect() {
		t.Error("MustReconnect default should be false")
	}
	s1.SetMustReconnect(true)
	if !s1.MustReconnect() {
		t.Error("MustReconnect after set")
	}
}

func TestConnStateCloseCancelsContext(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()

	s := NewConnState(a)
	if err := s.Context().Err(); err != nil {
		t.Fatalf("context already done: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-s.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("context not cancelled after Close")
	}
	if err := s.Context().Err(); err != context.Canceled {
		t.Errorf("ctx err = %v, want context.Canceled", err)
	}
}
