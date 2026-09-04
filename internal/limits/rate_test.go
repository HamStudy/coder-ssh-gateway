package limits

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/taxilian/coder-ssh-gateway/internal/config"
)

func TestRateLimitsPreAuthIP(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.ConnectionsPerIP = 16
	rl := newRateLimits(cfg.Limits, time.Now)

	ip := "1.2.3.4"

	// Should allow up to connections_per_ip (16) requests
	for i := 0; i < 16; i++ {
		if !rl.AllowPreAuthIP(ip) {
			t.Errorf("AllowPreAuthIP() round %d: got false, want true", i)
		}
	}

	// 17th should be rejected
	if rl.AllowPreAuthIP(ip) {
		t.Error("17th pre-auth request should be rejected")
	}
}

func TestRateLimitsUnknownKeyAttempt(t *testing.T) {
	cfg := config.Default()
	rl := newRateLimits(cfg.Limits, time.Now)

	ip := "5.6.7.8"

	// Default unknown_key_attempts is 10 per minute
	for i := 0; i < 10; i++ {
		if !rl.AllowUnknownKeyAttempt(ip) {
			t.Errorf("AllowUnknownKeyAttempt() round %d: got false, want true", i)
		}
	}

	// 11th should be rejected
	if rl.AllowUnknownKeyAttempt(ip) {
		t.Error("11th unknown key attempt should be rejected")
	}
}

func TestRateLimitsRenewalAttempt(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.RenewalAttemptsPerAccountPerMinute = 5
	rl := newRateLimits(cfg.Limits, time.Now)

	accountID := uuid.New()

	// Should allow up to 5 renewal attempts per minute
	for i := 0; i < 5; i++ {
		if !rl.AllowRenewalAttempt(accountID) {
			t.Errorf("AllowRenewalAttempt() round %d: got false, want true", i)
		}
	}

	// 6th should be rejected
	if rl.AllowRenewalAttempt(accountID) {
		t.Error("6th renewal attempt should be rejected")
	}
}

func TestRateLimitsReconnectAllowanceSingleUse(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.RenewalAttemptsPerAccountPerMinute = 3
	rl := newRateLimits(cfg.Limits, time.Now)

	accountID := uuid.New()

	// Exhaust the bucket
	for i := 0; i < 3; i++ {
		rl.AllowRenewalAttempt(accountID)
	}

	// 4th should be rejected (rate limited)
	if rl.AllowRenewalAttempt(accountID) {
		t.Error("should be rate limited without reconnect allowance")
	}

	// Grant reconnect allowance
	rl.GrantReconnectAllowance(accountID)

	// Now one more attempt should succeed
	if !rl.AllowRenewalAttempt(accountID) {
		t.Error("reconnect allowance should allow one attempt")
	}

	// But a second immediate attempt should fail (allowance consumed)
	if rl.AllowRenewalAttempt(accountID) {
		t.Error("reconnect allowance should be single-use")
	}
}

func TestRateLimitsReconnectAllowanceConsumedByNextAttempt(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.RenewalAttemptsPerAccountPerMinute = 2
	rl := newRateLimits(cfg.Limits, time.Now)

	accountID := uuid.New()

	// Exhaust the bucket
	rl.AllowRenewalAttempt(accountID)
	rl.AllowRenewalAttempt(accountID)

	// Grant reconnect allowance
	rl.GrantReconnectAllowance(accountID)

	// The FIRST AllowRenewalAttempt consumes the allowance
	if !rl.AllowRenewalAttempt(accountID) {
		t.Error("first attempt should consume allowance and succeed")
	}

	// Second attempt should be rejected (allowance consumed)
	if rl.AllowRenewalAttempt(accountID) {
		t.Error("second attempt should fail after allowance consumed")
	}
}

func TestRateLimitsFakeClockRefill(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.RenewalAttemptsPerAccountPerMinute = 3
	clock := &fakeClock{now: time.Now()}
	rl := newRateLimits(cfg.Limits, clock.Now)

	accountID := uuid.New()

	// Exhaust the bucket
	for i := 0; i < 3; i++ {
		rl.AllowRenewalAttempt(accountID)
	}

	if rl.AllowRenewalAttempt(accountID) {
		t.Error("should be rate limited at time zero")
	}

	// Advance clock by 61 seconds (bucket window)
	clock.now = clock.now.Add(61 * time.Second)

	// Should be able to acquire again
	if !rl.AllowRenewalAttempt(accountID) {
		t.Error("after 61s, should be able to acquire")
	}
}

func TestRateLimitsEvictionBoundedMap(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.ConnectionsPerIP = 16
	clock := &fakeClock{now: time.Now()}
	rl := newRateLimitsWithEviction(cfg.Limits, clock.Now, 10000, 10*time.Minute)

	// Create 20k distinct IPs - eviction should keep map bounded
	for i := 0; i < 20000; i++ {
		ip := uuid.New().String()
		rl.AllowPreAuthIP(ip)
	}

	// After eviction, map should be bounded
	rl.mu.Lock()
	mapSize := len(rl.ipBucket)
	rl.mu.Unlock()

	if mapSize > 15000 { // Allow some slack for in-flight entries
		t.Errorf("IP bucket map size %d too large after 20k entries", mapSize)
	}
}

func TestRateLimitsEvictionIdleCleanup(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.ConnectionsPerIP = 16
	clock := &fakeClock{now: time.Now()}
	rl := newRateLimitsWithEviction(cfg.Limits, clock.Now, 100, 1*time.Second)

	// Add some IPs
	for i := 0; i < 50; i++ {
		ip := uuid.New().String()
		rl.AllowPreAuthIP(ip)
	}

	// Advance time past the maxIdle duration
	clock.now = clock.now.Add(2 * time.Second)

	// Add another IP which triggers eviction sweep
	rl.AllowPreAuthIP("new-ip")

	// Old entries should have been evicted (at least some of them)
	rl.mu.Lock()
	mapSize := len(rl.ipBucket)
	rl.mu.Unlock()

	// With bounded eviction, we should be at or below targetSize (maxMapSize/2 = 50)
	// plus the new entry. But since all entries were idle, they should be cleaned up.
	if mapSize > 60 {
		t.Errorf("After idle eviction, map size %d still too large (expected <= 60)", mapSize)
	}
}

func TestRateLimitsConcurrentHammer(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.ConnectionsPerIP = 50
	cfg.Limits.RenewalAttemptsPerAccountPerMinute = 100
	clock := &fakeClock{now: time.Now()}
	rl := newRateLimitsWithEviction(cfg.Limits, clock.Now, 10000, 10*time.Minute)

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	start := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 10; j++ {
				ip := uuid.New().String()
				rl.AllowPreAuthIP(ip)
				accountID := uuid.New()
				rl.AllowRenewalAttempt(accountID)
			}
		}()
	}

	close(start)
	wg.Wait()

	// Should complete without deadlocks or OOM
}

func TestNewRateLimitsExportedConstructor(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.ConnectionsPerIP = 2
	cfg.Limits.RenewalAttemptsPerAccountPerMinute = 1
	rl := NewRateLimits(cfg.Limits)

	ip := "9.9.9.9"
	// Pre-auth IP gate: bucket of 2, third attempt rejected.
	if !rl.AllowPreAuthIP(ip) {
		t.Fatal("first pre-auth attempt should be allowed")
	}
	if !rl.AllowPreAuthIP(ip) {
		t.Fatal("second pre-auth attempt should be allowed")
	}
	if rl.AllowPreAuthIP(ip) {
		t.Error("pre-auth attempt beyond connections_per_ip should be rejected")
	}

	accountID := uuid.New()
	// Renewal gate: bucket of 1, second attempt rejected, reconnect
	// allowance admits exactly one more.
	if !rl.AllowRenewalAttempt(accountID) {
		t.Fatal("first renewal attempt should be allowed")
	}
	if rl.AllowRenewalAttempt(accountID) {
		t.Error("second renewal attempt should be rejected")
	}
	rl.GrantReconnectAllowance(accountID)
	if !rl.AllowRenewalAttempt(accountID) {
		t.Error("reconnect allowance should admit one attempt")
	}
	if rl.AllowRenewalAttempt(accountID) {
		t.Error("reconnect allowance should be single-use")
	}
}

type fakeClock struct {
	now time.Time
}

func (f *fakeClock) Now() time.Time {
	return f.now
}
