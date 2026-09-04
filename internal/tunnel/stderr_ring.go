package tunnel

import (
	"regexp"
	"slices"
	"sync"
)

// DefaultStderrRingBytes is the §19.7 bounded stderr collector size.
const DefaultStderrRingBytes = 64 * 1024

// tokenLike matches credential-looking runs (>=20 chars joined by '-'/'_'
// separator runs), mirroring the audit redaction heuristic but unanchored so
// it applies inside a text stream.
var tokenLike = regexp.MustCompile(`[A-Za-z0-9_-]{20,}[_-]+[A-Za-z0-9_-]*|[A-Za-z0-9_-]*[_-]+[A-Za-z0-9_-]{20,}`)

var redactedToken = []byte("[REDACTED]")

// StderrRing is the §19.7 bounded diagnostic collector for child stderr: it
// keeps only the LAST max bytes (the tail usually carries the actionable
// error), redacts token-like material defensively before storage, and never
// blocks the writer (mutex-protected drop-oldest, no I/O). Stderr content
// must never be merged into the protocol channel (§18.5).
type StderrRing struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func NewStderrRing(maxBytes int64) *StderrRing {
	if maxBytes <= 0 {
		maxBytes = DefaultStderrRingBytes
	}
	return &StderrRing{max: int(maxBytes)}
}

// Write implements io.Writer. It always consumes all of p and never blocks
// beyond the short critical section.
func (r *StderrRing) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	// Redact on the whole buffer so tokens split across writes are caught
	// once complete. The buffer is bounded, so the rescan cost is bounded.
	r.buf = tokenLike.ReplaceAll(r.buf, redactedToken)
	if len(r.buf) > r.max {
		excess := len(r.buf) - r.max
		r.buf = append(r.buf[:0], r.buf[excess:]...)
	}
	return len(p), nil
}

// Tail returns a defensive copy of the buffered tail.
func (r *StderrRing) Tail() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.buf)
}
