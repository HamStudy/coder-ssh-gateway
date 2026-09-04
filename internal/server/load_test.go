package server_test

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/config"
	"github.com/taxilian/coder-ssh-gateway/internal/metrics"
	"github.com/taxilian/coder-ssh-gateway/internal/server"
)

// fdCount returns the process open-fd count via /proc (linux-only repo).
func fdCount(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(ents)
}

// gatherCounter sums a counter family, optionally filtered to one label
// value on its first label dimension.
func gatherCounter(t *testing.T, m *metrics.Metrics, family, firstLabel string) float64 {
	t.Helper()
	mfs, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	var total float64
	for _, mf := range mfs {
		if mf.GetName() != family {
			continue
		}
		for _, metric := range mf.GetMetric() {
			if firstLabel != "" {
				labels := metric.GetLabel()
				if len(labels) == 0 || labels[0].GetValue() != firstLabel {
					continue
				}
			}
			total += metric.GetCounter().GetValue()
		}
	}
	return total
}

// TestLoadDoSResistance is the §20/§32 load+DoS gate: under a storm of 200
// concurrent unknown-key handshakes and 150 channel-open attempts against a
// server with scaled-down limits, a legitimate control connection must still
// authenticate within 5s, limits must reject cleanly (no panics, correct
// rejection reasons, metrics recorded), and the process must not leak file
// descriptors or goroutines after the storm drains.
func TestLoadDoSResistance(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(testCoderUserID))
	defer f.close(t)
	f.installCredential(t, "wire-token-load-test-0123456789")

	m := metrics.New()
	blocking := newFakeTunnelStarter("")
	blocking.gate = make(chan struct{})

	ts := startTestServer(t, f, func(sc *server.ServerConfig, lc *config.Config) {
		lc.Limits.UnauthenticatedConnections = 24
		lc.Limits.Handshakes = 12
		lc.Limits.ConnectionsPerIP = 20
		lc.Limits.ConnectionsPerKey = 8
		lc.Limits.ConnectionsPerAccount = 8
		lc.Limits.ChannelsPerConnection = 4
		lc.Limits.ChannelsPerAccount = 8
		lc.Limits.CoderProcesses = 8
		sc.TunnelStarter = blocking
		sc.Metrics = m
	})
	defer ts.shutdown(t)

	// Warm-up: one full auth so lazy allocations (verifier keep-alive conn,
	// store caches) exist before the fd baseline.
	warm, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("warm-up auth: %v", err)
	}
	warm.Close()
	fdBefore := fdCount(t)

	// Storm client: authenticate and hold all 4 per-connection channel slots
	// open (starter blocked on gate), so the 150-attempt storm exercises the
	// per-connection channel limit.
	stormClient, err := dialGateway(ts.addr(), "coder", ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("storm client auth: %v", err)
	}
	var held []ssh.Channel
	for i := 0; i < 4; i++ {
		ch, _, err := openDirectTCPIP(stormClient, "dev.coder-gateway.example.com", 22)
		if err != nil {
			t.Fatalf("hold channel %d: %v", i, err)
		}
		held = append(held, ch)
	}
	waitFor(t, 3*time.Second, func() bool { return len(blocking.recorded()) == 4 })

	unknownSigner := newClientSigner(t)

	var wg sync.WaitGroup
	handshakeErrs := make(chan error, 200)
	channelErrs := make(chan error, 150)

	// Storm A: 200 concurrent unknown-key handshakes (all must fail).
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := ssh.Dial("tcp", ts.addr(), &ssh.ClientConfig{
				User:            "coder",
				Auth:            []ssh.AuthMethod{ssh.PublicKeys(unknownSigner)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         10 * time.Second,
			})
			if err == nil {
				c.Close()
				handshakeErrs <- errors.New("unknown key unexpectedly authenticated")
				return
			}
			handshakeErrs <- nil
		}()
	}

	// Storm B: 150 channel-open attempts against the exhausted per-conn limit.
	for i := 0; i < 150; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, _, err := openDirectTCPIP(stormClient, "dev.coder-gateway.example.com", 22)
			if err == nil {
				ch.Close()
				channelErrs <- errors.New("channel open unexpectedly succeeded past the limit")
				return
			}
			if reason, ok := openChannelReason(err); !ok || reason != ssh.ResourceShortage {
				channelErrs <- fmt.Errorf("channel rejection = %v, want OpenChannelError ResourceShortage", err)
				return
			}
			channelErrs <- nil
		}()
	}

	// DURING the storm: a control connection must still authenticate in 5s.
	dialDeadline := time.Now().Add(5 * time.Second)
	var ctrl *ssh.Client
	for time.Now().Before(dialDeadline) {
		c, err := ssh.Dial("tcp", ts.addr(), &ssh.ClientConfig{
			User:            "coder",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(f.signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         time.Second,
		})
		if err == nil {
			ctrl = c
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if ctrl == nil {
		t.Fatal("control connection failed to authenticate within 5s during the storm")
	}
	ctrl.Close()

	wg.Wait()
	close(handshakeErrs)
	close(channelErrs)
	for err := range handshakeErrs {
		if err != nil {
			t.Errorf("handshake storm: %v", err)
		}
	}
	for err := range channelErrs {
		if err != nil {
			t.Errorf("channel storm: %v", err)
		}
	}

	// Limits rejected cleanly: metric evidence of both storms.
	if got := gatherCounter(t, m, "coder_ssh_gateway_limit_rejections_total", ""); got == 0 {
		t.Error("limit_rejections_total = 0; want > 0 after the storms")
	}
	if got := gatherCounter(t, m, "coder_ssh_gateway_channels_total", "rejected"); got < 150 {
		t.Errorf("channels_total{result=rejected} = %v, want >= 150", got)
	}

	// Cleanup: release the blocked starters, close the held channels and the
	// storm client, then wait for the fd count to settle near baseline.
	close(blocking.gate)
	for _, ch := range held {
		ch.Close()
	}
	stormClient.Close()

	waitFor(t, 10*time.Second, func() bool {
		n := fdCount(t)
		return n >= fdBefore-5 && n <= fdBefore+5
	})
	t.Logf("fd count: before=%d after=%d", fdBefore, fdCount(t))
}
