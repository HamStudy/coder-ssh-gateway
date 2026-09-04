package limits

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/taxilian/coder-ssh-gateway/internal/config"
	"go.uber.org/goleak"
)

// TestMain enables leak detection for all tests in this package.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestCountersGlobalConnBoundary(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.UnauthenticatedConnections = 5
	c := New(cfg)

	// Acquire up to the limit
	for i := 0; i < 5; i++ {
		release, ok := c.AcquireGlobal()
		if !ok {
			t.Fatalf("AcquireGlobal() round %d: got ok=false, want true", i)
		}
		if release == nil {
			t.Fatal("AcquireGlobal() returned nil release")
		}
	}

	// The 6th should be rejected
	_, ok := c.AcquireGlobal()
	if ok {
		t.Error("AcquireGlobal() 6th call: got ok=true, want false (limit is 5)")
	}
}

func TestCountersGlobalConnRelease(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.UnauthenticatedConnections = 3
	c := New(cfg)

	// Acquire 3
	rel1, _ := c.AcquireGlobal()
	_, _ = c.AcquireGlobal()
	_, _ = c.AcquireGlobal()

	// 4th should fail
	_, ok := c.AcquireGlobal()
	if ok {
		t.Fatal("should be at capacity")
	}

	// Release one
	rel1()

	// Now one slot should be available
	_, ok = c.AcquireGlobal()
	if !ok {
		t.Error("after release, should be able to acquire")
	}
}

func TestCountersGlobalConnDeferPanic(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.UnauthenticatedConnections = 2
	c := New(cfg)

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("caught expected panic: %v", r)
			}
		}()
		rel, ok := c.AcquireGlobal()
		if !ok {
			t.Fatal("should acquire")
		}
		defer rel()
		panic("simulated error")
	}()

	// After panic+defer, the slot should be released
	_, ok := c.AcquireGlobal()
	if !ok {
		t.Error("slot should be available after panic deferred release")
	}
}

func TestCountersHandshakeBoundary(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.Handshakes = 4
	c := New(cfg)

	releases := make([]func(), 0, 4)
	for i := 0; i < 4; i++ {
		rel, ok := c.AcquireHandshake()
		if !ok {
			t.Fatalf("AcquireHandshake() round %d: got false, want true", i)
		}
		releases = append(releases, rel)
	}

	_, ok := c.AcquireHandshake()
	if ok {
		t.Error("over limit: should be rejected")
	}

	releases[0]()
	_, ok = c.AcquireHandshake()
	if !ok {
		t.Error("after release, should be able to acquire")
	}
}

func TestCountersIPBoundary(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.ConnectionsPerIP = 3
	c := New(cfg)

	ip := "192.168.1.1"
	releases := make([]func(), 0, 3)
	for i := 0; i < 3; i++ {
		rel, ok := c.AcquireIP(ip)
		if !ok {
			t.Fatalf("AcquireIP() round %d: got false, want true", i)
		}
		releases = append(releases, rel)
	}

	_, ok := c.AcquireIP(ip)
	if ok {
		t.Error("per-IP limit exceeded")
	}

	releases[0]()
	_, ok = c.AcquireIP(ip)
	if !ok {
		t.Error("after release, should be able to acquire")
	}

	// Different IP should work
	_, ok = c.AcquireIP("10.0.0.1")
	if !ok {
		t.Error("different IP should have its own counter")
	}
}

func TestCountersKeyBoundary(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.ConnectionsPerKey = 2
	c := New(cfg)

	keyID := uuid.New()
	releases := make([]func(), 0, 2)
	for i := 0; i < 2; i++ {
		rel, ok := c.AcquireKey(keyID)
		if !ok {
			t.Fatalf("AcquireKey() round %d: got false, want true", i)
		}
		releases = append(releases, rel)
	}

	_, ok := c.AcquireKey(keyID)
	if ok {
		t.Error("per-key limit exceeded")
	}

	releases[0]()
	_, ok = c.AcquireKey(keyID)
	if !ok {
		t.Error("after release, should be able to acquire")
	}
}

func TestCountersAccountBoundary(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.ConnectionsPerAccount = 2
	c := New(cfg)

	accountID := uuid.New()
	releases := make([]func(), 0, 2)
	for i := 0; i < 2; i++ {
		rel, ok := c.AcquireAccount(accountID)
		if !ok {
			t.Fatalf("AcquireAccount() round %d: got false, want true", i)
		}
		releases = append(releases, rel)
	}

	_, ok := c.AcquireAccount(accountID)
	if ok {
		t.Error("per-account limit exceeded")
	}

	releases[0]()
	_, ok = c.AcquireAccount(accountID)
	if !ok {
		t.Error("after release, should be able to acquire")
	}
}

func TestCountersChannelBoundary(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.ChannelsPerConnection = 2
	c := New(cfg)

	connID := "conn-abc"
	releases := make([]func(), 0, 2)
	for i := 0; i < 2; i++ {
		rel, ok := c.AcquireChannel(connID)
		if !ok {
			t.Fatalf("AcquireChannel() round %d: got false, want true", i)
		}
		releases = append(releases, rel)
	}

	_, ok := c.AcquireChannel(connID)
	if ok {
		t.Error("per-connection channel limit exceeded")
	}

	releases[0]()
	_, ok = c.AcquireChannel(connID)
	if !ok {
		t.Error("after release, should be able to acquire")
	}
}

func TestCountersChannelAccountBoundary(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.ChannelsPerAccount = 3
	c := New(cfg)

	accountID := uuid.New()
	releases := make([]func(), 0, 3)
	for i := 0; i < 3; i++ {
		rel, ok := c.AcquireChannelAccount(accountID)
		if !ok {
			t.Fatalf("AcquireChannelAccount() round %d: got false, want true", i)
		}
		releases = append(releases, rel)
	}

	_, ok := c.AcquireChannelAccount(accountID)
	if ok {
		t.Error("per-account channel limit exceeded")
	}

	releases[0]()
	_, ok = c.AcquireChannelAccount(accountID)
	if !ok {
		t.Error("after release, should be able to acquire")
	}
}

func TestCountersCoderProcessBoundary(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.CoderProcesses = 2
	c := New(cfg)

	releases := make([]func(), 0, 2)
	for i := 0; i < 2; i++ {
		rel, ok := c.AcquireCoderProcess()
		if !ok {
			t.Fatalf("AcquireCoderProcess() round %d: got false, want true", i)
		}
		releases = append(releases, rel)
	}

	_, ok := c.AcquireCoderProcess()
	if ok {
		t.Error("coder process limit exceeded")
	}

	releases[0]()
	_, ok = c.AcquireCoderProcess()
	if !ok {
		t.Error("after release, should be able to acquire")
	}
}

func TestCountersCoderAPIBoundary(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.CoderAPIRequests = 2
	c := New(cfg)

	releases := make([]func(), 0, 2)
	for i := 0; i < 2; i++ {
		rel, ok := c.AcquireCoderAPI()
		if !ok {
			t.Fatalf("AcquireCoderAPI() round %d: got false, want true", i)
		}
		releases = append(releases, rel)
	}

	_, ok := c.AcquireCoderAPI()
	if ok {
		t.Error("coder API limit exceeded")
	}

	releases[0]()
	_, ok = c.AcquireCoderAPI()
	if !ok {
		t.Error("after release, should be able to acquire")
	}
}

func TestCountersUsage(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.UnauthenticatedConnections = 100
	cfg.Limits.Handshakes = 50
	cfg.Limits.ConnectionsPerIP = 10
	cfg.Limits.ConnectionsPerKey = 5
	cfg.Limits.ConnectionsPerAccount = 5
	cfg.Limits.ChannelsPerConnection = 4
	cfg.Limits.ChannelsPerAccount = 8
	cfg.Limits.CoderProcesses = 20
	cfg.Limits.CoderAPIRequests = 10
	c := New(cfg)

	// Acquire some resources
	c.AcquireGlobal()
	c.AcquireGlobal()
	c.AcquireHandshake()
	ip := "1.2.3.4"
	c.AcquireIP(ip)
	keyID := uuid.New()
	c.AcquireKey(keyID)
	accountID := uuid.New()
	c.AcquireAccount(accountID)
	c.AcquireChannel("conn-1")
	c.AcquireChannelAccount(accountID)
	c.AcquireCoderProcess()
	c.AcquireCoderAPI()

	u := c.Usage()
	if u.GlobalConns != 2 {
		t.Errorf("GlobalConns: got %d, want 2", u.GlobalConns)
	}
	if u.Handshakes != 1 {
		t.Errorf("Handshakes: got %d, want 1", u.Handshakes)
	}
	if u.IPs[ip] != 1 {
		t.Errorf("IPs[%s]: got %d, want 1", ip, u.IPs[ip])
	}
	if u.Keys[keyID] != 1 {
		t.Errorf("Keys[%s]: got %d, want 1", keyID, u.Keys[keyID])
	}
	if u.Accounts[accountID] != 1 {
		t.Errorf("Accounts[%s]: got %d, want 1", accountID, u.Accounts[accountID])
	}
	if u.Channels["conn-1"] != 1 {
		t.Errorf("Channels[conn-1]: got %d, want 1", u.Channels["conn-1"])
	}
	if u.ChannelAccounts[accountID] != 1 {
		t.Errorf("ChannelAccounts[%s]: got %d, want 1", accountID, u.ChannelAccounts[accountID])
	}
	if u.CoderProcesses != 1 {
		t.Errorf("CoderProcesses: got %d, want 1", u.CoderProcesses)
	}
	if u.CoderAPIRequests != 1 {
		t.Errorf("CoderAPIRequests: got %d, want 1", u.CoderAPIRequests)
	}
}

func TestCountersConcurrentHammer(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.UnauthenticatedConnections = 50
	cfg.Limits.ConnectionsPerIP = 10
	cfg.Limits.ConnectionsPerKey = 8
	cfg.Limits.ConnectionsPerAccount = 8
	cfg.Limits.CoderProcesses = 30
	c := New(cfg)

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	start := make(chan struct{})
	done := make(chan struct{}, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			gRel, gOk := c.AcquireGlobal()
			if gOk {
				defer gRel()
			}
			ip := uuid.New().String()
			ipRel, ipOk := c.AcquireIP(ip)
			if ipOk {
				defer ipRel()
			}
			keyID := uuid.New()
			kRel, kOk := c.AcquireKey(keyID)
			if kOk {
				defer kRel()
			}
			accID := uuid.New()
			aRel, aOk := c.AcquireAccount(accID)
			if aOk {
				defer aRel()
			}
			pRel, pOk := c.AcquireCoderProcess()
			if pOk {
				defer pRel()
			}
			relCh, _ := c.AcquireChannel(uuid.New().String())
			if relCh != nil {
				defer relCh()
			}
			relChAcc, _ := c.AcquireChannelAccount(uuid.New())
			if relChAcc != nil {
				defer relChAcc()
			}
			select {
			case done <- struct{}{}:
			default:
			}
		}()
	}

	close(start)

	timeout := time.After(10 * time.Second)
	for i := 0; i < goroutines; i++ {
		select {
		case <-done:
		case <-timeout:
			t.Fatal("timeout waiting for goroutines")
		}
	}
	wg.Wait()

	u := c.Usage()
	if u.GlobalConns > cfg.Limits.UnauthenticatedConnections {
		t.Errorf("GlobalConns %d exceeds limit %d", u.GlobalConns, cfg.Limits.UnauthenticatedConnections)
	}
	if u.CoderProcesses > cfg.Limits.CoderProcesses {
		t.Errorf("CoderProcesses %d exceeds limit %d", u.CoderProcesses, cfg.Limits.CoderProcesses)
	}
}

func TestCountersReleaseOnceSafety(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.UnauthenticatedConnections = 2
	c := New(cfg)

	rel, ok := c.AcquireGlobal()
	if !ok {
		t.Fatal("should acquire")
	}

	// First release
	rel()
	// Second release - should be no-op (sync.Once)
	rel()

	// Should still only be one slot used
	_, ok = c.AcquireGlobal()
	if !ok {
		t.Error("second release should not double-release")
	}
}

func TestCountersAllLimitsFromConfig(t *testing.T) {
	cfg := config.Default()
	// All limits are already set from config.Default()
	c := New(cfg)

	// Verify we can acquire and release all limit types
	limits := []struct {
		name   string
		acquire func() (func(), bool)
	}{
		{"Global", c.AcquireGlobal},
		{"Handshake", c.AcquireHandshake},
		{"IP", func() (func(), bool) { return c.AcquireIP("10.0.0.1") }},
		{"Key", func() (func(), bool) { return c.AcquireKey(uuid.New()) }},
		{"Account", func() (func(), bool) { return c.AcquireAccount(uuid.New()) }},
		{"Channel", func() (func(), bool) { return c.AcquireChannel("conn-x") }},
		{"ChannelAccount", func() (func(), bool) { return c.AcquireChannelAccount(uuid.New()) }},
		{"CoderProcess", c.AcquireCoderProcess},
		{"CoderAPI", c.AcquireCoderAPI},
	}

	for _, tt := range limits {
		t.Run(tt.name, func(t *testing.T) {
			rel, ok := tt.acquire()
			if !ok {
				t.Errorf("%s: failed to acquire", tt.name)
				return
			}
			if rel == nil {
				t.Errorf("%s: got nil release", tt.name)
				return
			}
			rel()
		})
	}
}
