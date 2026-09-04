package sshauth

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/core"
)

// ConnState holds the mutable per-connection state that the per-connection
// auth callbacks close over (§9.4). Exactly one ConnState exists per accepted
// TCP connection; it is created before the SSH handshake so a random
// connection ID is available for logs and audit even when authentication
// never completes (§34.4).
//
// Auth callbacks run on the ssh handshake goroutine, while the pre-auth conn
// may be installed from PreAuthConnCallback on the same goroutine; a mutex
// still guards the mutable fields so the connection owner (T15) can safely
// read state after NewServerConn returns.
type ConnState struct {
	id       string
	rawConn  net.Conn
	peerAddr string

	ctx    context.Context
	cancel context.CancelFunc

	mu           sync.Mutex
	preAuthConn  ssh.ServerPreAuthConn
	candidate    *candidateIdentity
	verified     *verifiedIdentity
	renewalTries int
	reconnect    bool
}

// candidateIdentity is set by the public-key candidate callback after a
// successful store lookup. It lets the verified-key callback recover the full
// account/key records without widening the store interface.
type candidateIdentity struct {
	account   core.Account
	keyRecord core.SSHKeyRecord
}

// verifiedIdentity records proof-of-possession details once the client has
// produced a valid signature.
type verifiedIdentity struct {
	account            core.Account
	keyRecord          core.SSHKeyRecord
	signatureAlgorithm string
}

// NewConnState creates per-connection state for an accepted raw connection.
// raw must be non-nil. The connection ID is random and generated here, before
// the SSH handshake (§34.4).
func NewConnState(raw net.Conn) *ConnState {
	ctx, cancel := context.WithCancel(context.Background())
	peer := ""
	if addr := raw.RemoteAddr(); addr != nil {
		peer = addr.String()
	}
	return &ConnState{
		id:       uuid.NewString(),
		rawConn:  raw,
		peerAddr: peer,
		ctx:      ctx,
		cancel:   cancel,
	}
}

// ID returns the random connection ID generated before the handshake.
func (s *ConnState) ID() string { return s.id }

// PeerAddr returns the remote address string captured at accept time.
func (s *ConnState) PeerAddr() string { return s.peerAddr }

// RawConn returns the underlying accepted connection.
func (s *ConnState) RawConn() net.Conn { return s.rawConn }

// Context returns a context cancelled when Close is called. Auth callbacks
// use it for store and Coder API calls so they unwind on connection teardown.
func (s *ConnState) Context() context.Context { return s.ctx }

// Close cancels the connection context and closes the raw connection. It is
// idempotent.
func (s *ConnState) Close() error {
	s.cancel()
	return s.rawConn.Close()
}

// SetPreAuthConn records the ServerPreAuthConn for banner delivery (§9.6).
// Called from PreAuthConnCallback.
func (s *ConnState) SetPreAuthConn(c ssh.ServerPreAuthConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preAuthConn = c
}

// SetDeadline applies an absolute deadline to the raw connection (§13.5
// phase-aware deadlines: extended when renewal starts, cleared after auth).
func (s *ConnState) SetDeadline(t time.Time) error {
	return s.rawConn.SetDeadline(t)
}

// SendBanner delivers an authentication banner through the pre-auth
// connection (§9.6). It is a no-op when no pre-auth connection is installed
// yet, and banner write failures are swallowed: banner delivery is
// best-effort and must never change the authentication outcome.
func (s *ConnState) SendBanner(msg string) {
	s.mu.Lock()
	c := s.preAuthConn
	s.mu.Unlock()
	if c == nil {
		return
	}
	_ = c.SendAuthBanner(msg)
}

// setCandidate records the resolved account/key pair from a successful
// candidate lookup. Unexported: only the public-key callback sets it.
func (s *ConnState) setCandidate(account core.Account, keyRecord core.SSHKeyRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.candidate = &candidateIdentity{account: account, keyRecord: keyRecord}
}

// candidateFor returns the stashed candidate identity only when it matches
// the IDs carried in the (server-generated, client-echoed) candidate
// permissions. A mismatch means the permissions were tampered with.
func (s *ConnState) candidateFor(accountID, keyID uuid.UUID) (core.Account, core.SSHKeyRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.candidate == nil {
		return core.Account{}, core.SSHKeyRecord{}, false
	}
	if s.candidate.account.ID != accountID || s.candidate.keyRecord.ID != keyID {
		return core.Account{}, core.SSHKeyRecord{}, false
	}
	return s.candidate.account, s.candidate.keyRecord, true
}

// SetVerifiedIdentity records proof of possession (§9.3): the verified
// account, key record, and the signature algorithm the client used.
func (s *ConnState) SetVerifiedIdentity(account core.Account, keyRecord core.SSHKeyRecord, signatureAlgorithm string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verified = &verifiedIdentity{
		account:            account,
		keyRecord:          keyRecord,
		signatureAlgorithm: signatureAlgorithm,
	}
}

// VerifiedIdentity reports whether the client has proven possession of a
// registered private key, and returns the verified identity if so.
func (s *ConnState) VerifiedIdentity() (core.Account, core.SSHKeyRecord, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.verified == nil {
		return core.Account{}, core.SSHKeyRecord{}, "", false
	}
	return s.verified.account, s.verified.keyRecord, s.verified.signatureAlgorithm, true
}

// IncrementRenewalAttempts bumps and returns the per-connection renewal
// attempt counter (§13.2 bounds token attempts per connection; T20 enforces).
func (s *ConnState) IncrementRenewalAttempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.renewalTries++
	return s.renewalTries
}

// RenewalAttempts returns the current renewal attempt count.
func (s *ConnState) RenewalAttempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.renewalTries
}

// SetMustReconnect records whether the connection must close after auth
// (§13.6 forced reconnect after credential renewal).
func (s *ConnState) SetMustReconnect(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconnect = v
}

// MustReconnect reports the forced-reconnect flag.
func (s *ConnState) MustReconnect() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reconnect
}
