package limits

import (
	"sync"

	"github.com/HamStudy/coder-ssh-gateway/internal/config"
	"github.com/google/uuid"
)

type Reason string

const (
	ReasonGlobalConn        Reason = "global_conn"
	ReasonHandshake         Reason = "handshake"
	ReasonIPConn            Reason = "ip_conn"
	ReasonKeyConn           Reason = "key_conn"
	ReasonAccountConn       Reason = "account_conn"
	ReasonChannelConn       Reason = "channel_conn"
	ReasonChannelAccount    Reason = "channel_account"
	ReasonCoderProcess      Reason = "coder_process"
	ReasonCoderAPI          Reason = "coder_api"
	ReasonPreAuthIP         Reason = "pre_auth_ip"
	ReasonUnknownKeyAttempt Reason = "unknown_key_attempt"
	ReasonRenewalRate       Reason = "renewal_rate"
)

type semaphore struct {
	mu    sync.Mutex
	count int
	max   int
}

func (s *semaphore) Acquire() (release func(), ok bool) {
	s.mu.Lock()
	if s.count >= s.max {
		s.mu.Unlock()
		return nil, false
	}
	s.count++
	s.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			s.count--
			s.mu.Unlock()
		})
	}, true
}

func acquireMapped[K comparable](
	mu *sync.RWMutex,
	entries map[K]*semaphore,
	key K,
	max int,
) (release func(), ok bool) {
	mu.Lock()
	s, exists := entries[key]
	if !exists {
		if max <= 0 {
			mu.Unlock()
			return nil, false
		}
		s = &semaphore{max: max}
		entries[key] = s
	}

	s.mu.Lock()
	if s.count >= s.max {
		s.mu.Unlock()
		mu.Unlock()
		return nil, false
	}
	s.count++
	s.mu.Unlock()
	mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			// Keep lookup, count changes, and deletion under the map-first lock
			// order so no acquisition can attach to an entry being removed.
			mu.Lock()
			s.mu.Lock()
			s.count--
			if s.count == 0 && entries[key] == s {
				delete(entries, key)
			}
			s.mu.Unlock()
			mu.Unlock()
		})
	}, true
}

type Counters struct {
	globalConn      semaphore
	handshake       semaphore
	ipConns         map[string]*semaphore
	ipConnsMu       sync.RWMutex
	maxIPConns      int
	keyConns        map[uuid.UUID]*semaphore
	keyConnsMu      sync.RWMutex
	maxKeyConns     int
	accountConns    map[uuid.UUID]*semaphore
	accountConnsMu  sync.RWMutex
	maxAccountConns int
	channels        map[string]*semaphore
	channelsMu      sync.RWMutex
	maxChannels     int
	channelAccounts map[uuid.UUID]*semaphore
	channelAcctsMu  sync.RWMutex
	maxChannelAccts int
	coderProcess    semaphore
	coderAPI        semaphore
}

func New(cfg *config.Config) *Counters {
	return &Counters{
		globalConn:      semaphore{max: cfg.Limits.UnauthenticatedConnections},
		handshake:       semaphore{max: cfg.Limits.Handshakes},
		ipConns:         make(map[string]*semaphore),
		maxIPConns:      cfg.Limits.ConnectionsPerIP,
		keyConns:        make(map[uuid.UUID]*semaphore),
		maxKeyConns:     cfg.Limits.ConnectionsPerKey,
		accountConns:    make(map[uuid.UUID]*semaphore),
		maxAccountConns: cfg.Limits.ConnectionsPerAccount,
		channels:        make(map[string]*semaphore),
		maxChannels:     cfg.Limits.ChannelsPerConnection,
		channelAccounts: make(map[uuid.UUID]*semaphore),
		maxChannelAccts: cfg.Limits.ChannelsPerAccount,
		coderProcess:    semaphore{max: cfg.Limits.CoderProcesses},
		coderAPI:        semaphore{max: cfg.Limits.CoderAPIRequests},
	}
}

func (c *Counters) AcquireGlobal() (func(), bool) {
	return c.globalConn.Acquire()
}

func (c *Counters) AcquireHandshake() (func(), bool) {
	return c.handshake.Acquire()
}

func (c *Counters) AcquireIP(ip string) (func(), bool) {
	return acquireMapped(&c.ipConnsMu, c.ipConns, ip, c.maxIPConns)
}

func (c *Counters) AcquireKey(keyID uuid.UUID) (func(), bool) {
	return acquireMapped(&c.keyConnsMu, c.keyConns, keyID, c.maxKeyConns)
}

func (c *Counters) AcquireAccount(accountID uuid.UUID) (func(), bool) {
	return acquireMapped(&c.accountConnsMu, c.accountConns, accountID, c.maxAccountConns)
}

func (c *Counters) AcquireChannel(connID string) (func(), bool) {
	return acquireMapped(&c.channelsMu, c.channels, connID, c.maxChannels)
}

func (c *Counters) AcquireChannelAccount(accountID uuid.UUID) (func(), bool) {
	return acquireMapped(
		&c.channelAcctsMu,
		c.channelAccounts,
		accountID,
		c.maxChannelAccts,
	)
}

func (c *Counters) AcquireCoderProcess() (func(), bool) {
	return c.coderProcess.Acquire()
}

func (c *Counters) AcquireCoderAPI() (func(), bool) {
	return c.coderAPI.Acquire()
}

type LimitsUsage struct {
	GlobalConns      int
	Handshakes       int
	IPs              map[string]int
	Keys             map[uuid.UUID]int
	Accounts         map[uuid.UUID]int
	Channels         map[string]int
	ChannelAccounts  map[uuid.UUID]int
	CoderProcesses   int
	CoderAPIRequests int
}

func (c *Counters) Usage() LimitsUsage {
	c.ipConnsMu.RLock()
	ips := make(map[string]int, len(c.ipConns))
	for ip, s := range c.ipConns {
		s.mu.Lock()
		ips[ip] = s.count
		s.mu.Unlock()
	}
	c.ipConnsMu.RUnlock()

	c.keyConnsMu.RLock()
	keys := make(map[uuid.UUID]int, len(c.keyConns))
	for id, s := range c.keyConns {
		s.mu.Lock()
		keys[id] = s.count
		s.mu.Unlock()
	}
	c.keyConnsMu.RUnlock()

	c.accountConnsMu.RLock()
	accounts := make(map[uuid.UUID]int, len(c.accountConns))
	for id, s := range c.accountConns {
		s.mu.Lock()
		accounts[id] = s.count
		s.mu.Unlock()
	}
	c.accountConnsMu.RUnlock()

	c.channelsMu.RLock()
	channels := make(map[string]int, len(c.channels))
	for id, s := range c.channels {
		s.mu.Lock()
		channels[id] = s.count
		s.mu.Unlock()
	}
	c.channelsMu.RUnlock()

	c.channelAcctsMu.RLock()
	channelAccts := make(map[uuid.UUID]int, len(c.channelAccounts))
	for id, s := range c.channelAccounts {
		s.mu.Lock()
		channelAccts[id] = s.count
		s.mu.Unlock()
	}
	c.channelAcctsMu.RUnlock()

	c.globalConn.mu.Lock()
	globalConns := c.globalConn.count
	c.globalConn.mu.Unlock()

	c.handshake.mu.Lock()
	handshakes := c.handshake.count
	c.handshake.mu.Unlock()

	c.coderProcess.mu.Lock()
	coderProcs := c.coderProcess.count
	c.coderProcess.mu.Unlock()

	c.coderAPI.mu.Lock()
	coderAPI := c.coderAPI.count
	c.coderAPI.mu.Unlock()

	return LimitsUsage{
		GlobalConns:      globalConns,
		Handshakes:       handshakes,
		IPs:              ips,
		Keys:             keys,
		Accounts:         accounts,
		Channels:         channels,
		ChannelAccounts:  channelAccts,
		CoderProcesses:   coderProcs,
		CoderAPIRequests: coderAPI,
	}
}
