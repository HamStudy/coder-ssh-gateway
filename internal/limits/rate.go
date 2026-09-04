package limits

import (
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/taxilian/coder-ssh-gateway/internal/config"
)

type tokenBucket struct {
	tokens     int
	maxTokens  int
	lastRefill time.Time
	refillRate time.Duration
}

func newTokenBucket(max int, refillPerMin int) *tokenBucket {
	return &tokenBucket{
		tokens:     max,
		maxTokens:  max,
		lastRefill: time.Now(),
		refillRate: time.Minute / time.Duration(refillPerMin),
	}
}

func (tb *tokenBucket) Allow(now time.Time) bool {
	tb.refill(now)
	if tb.tokens > 0 {
		tb.tokens--
		return true
	}
	return false
}

func (tb *tokenBucket) refill(now time.Time) {
	elapsed := now.Sub(tb.lastRefill)
	if elapsed < tb.refillRate {
		return
	}
	tokensToAdd := int(elapsed / tb.refillRate)
	if tokensToAdd > 0 {
		tb.tokens = min(tb.maxTokens, tb.tokens+tokensToAdd)
		tb.lastRefill = now
	}
}

type RateLimits struct {
	mu                  sync.Mutex
	preAuthIP           map[string]*tokenBucket
	maxPreAuthIP        int
	ipBucket            map[string]*bucketEntry
	muIP                sync.Mutex
	keyBucket           map[string]*tokenBucket
	accountBucket       map[uuid.UUID]*accountBucketEntry
	muAccount           sync.Mutex
	clock               func() time.Time
	maxMapSize          int
	maxIdle             time.Duration
	renewalAttemptsPerMin int
}

type bucketEntry struct {
	bucket    *tokenBucket
	lastSeen  time.Time
}

type accountBucketEntry struct {
	bucket      *tokenBucket
	lastSeen    time.Time
	allowance   bool
	allowanceMu sync.Mutex
}

// NewRateLimits constructs the production §20 rate limiter (pre-auth IP
// gate, unknown-key gate, and the per-account renewal gate with the §13.6
// single-use reconnect allowance) from the limits configuration, using the
// real clock and the default eviction bounds. Connection semaphores are
// separate: see New.
func NewRateLimits(l config.Limits) *RateLimits {
	return newRateLimits(l, time.Now)
}

func newRateLimits(l config.Limits, clock func() time.Time) *RateLimits {
	return newRateLimitsWithEviction(l, clock, 10000, 10*time.Minute)
}

func newRateLimitsWithEviction(l config.Limits, clock func() time.Time, maxMapSize int, maxIdle time.Duration) *RateLimits {
	if clock == nil {
		clock = time.Now
	}
	return &RateLimits{
		preAuthIP:             make(map[string]*tokenBucket),
		maxPreAuthIP:          l.ConnectionsPerIP,
		ipBucket:              make(map[string]*bucketEntry),
		keyBucket:             make(map[string]*tokenBucket),
		accountBucket:         make(map[uuid.UUID]*accountBucketEntry),
		clock:                 clock,
		maxMapSize:            maxMapSize,
		maxIdle:               maxIdle,
		renewalAttemptsPerMin: l.RenewalAttemptsPerAccountPerMinute,
	}
}

func (r *RateLimits) AllowPreAuthIP(ip string) bool {
	r.muIP.Lock()
	defer r.muIP.Unlock()

	entry, exists := r.ipBucket[ip]
	now := r.clock()
	if !exists {
		r.evictIfNeededLocked(now)
		entry = &bucketEntry{
			bucket:    newTokenBucket(r.maxPreAuthIP, r.maxPreAuthIP),
			lastSeen:  now,
		}
		r.ipBucket[ip] = entry
	}
	entry.lastSeen = now
	return entry.bucket.Allow(now)
}

func (r *RateLimits) evictIfNeededLocked(now time.Time) {
	targetSize := r.maxMapSize / 2
	if targetSize < 100 {
		targetSize = 100
	}

	currentSize := len(r.ipBucket)
	if currentSize < targetSize {
		return
	}

	idleCutoff := now.Add(-r.maxIdle)

	idleEntries := make([]string, 0)
	otherEntries := make([]string, 0)
	for ip, entry := range r.ipBucket {
		if entry.lastSeen.Before(idleCutoff) {
			idleEntries = append(idleEntries, ip)
		} else {
			otherEntries = append(otherEntries, ip)
		}
	}

	// If all entries are idle, delete them all
	if len(otherEntries) == 0 {
		for _, ip := range idleEntries {
			delete(r.ipBucket, ip)
		}
		return
	}

	entriesToDelete := currentSize - targetSize
	if entriesToDelete <= 0 {
		return
	}

	deleted := 0
	for _, ip := range idleEntries {
		delete(r.ipBucket, ip)
		deleted++
		if deleted >= entriesToDelete {
			return
		}
	}

	for _, ip := range otherEntries {
		delete(r.ipBucket, ip)
		deleted++
		if deleted >= entriesToDelete {
			return
		}
	}
}

func (r *RateLimits) AllowUnknownKeyAttempt(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	bucket, exists := r.keyBucket[ip]
	if !exists {
		bucket = newTokenBucket(10, 10)
		r.keyBucket[ip] = bucket
	}
	return bucket.Allow(r.clock())
}

func (r *RateLimits) AllowRenewalAttempt(accountID uuid.UUID) bool {
	r.muAccount.Lock()
	defer r.muAccount.Unlock()

	entry, exists := r.accountBucket[accountID]
	now := r.clock()
	if !exists {
		entry = &accountBucketEntry{
			bucket:   newTokenBucket(r.renewalAttemptsPerMin, r.renewalAttemptsPerMin),
			lastSeen: now,
		}
		r.accountBucket[accountID] = entry
		return entry.bucket.Allow(now)
	}

	entry.lastSeen = now

	entry.allowanceMu.Lock()
	hasAllowance := entry.allowance
	if hasAllowance {
		entry.allowance = false
	}
	entry.allowanceMu.Unlock()

	if hasAllowance {
		return true
	}

	return entry.bucket.Allow(now)
}

func (r *RateLimits) GrantReconnectAllowance(accountID uuid.UUID) {
	r.muAccount.Lock()
	defer r.muAccount.Unlock()

	entry, exists := r.accountBucket[accountID]
	if !exists {
		entry = &accountBucketEntry{
			bucket:   newTokenBucket(r.renewalAttemptsPerMin, r.renewalAttemptsPerMin),
			lastSeen: r.clock(),
		}
		r.accountBucket[accountID] = entry
	}

	entry.allowanceMu.Lock()
	entry.allowance = true
	entry.allowanceMu.Unlock()
}
