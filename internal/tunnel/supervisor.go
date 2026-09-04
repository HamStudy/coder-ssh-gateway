package tunnel

import (
	"context"
	"io"
	"log/slog"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/core"
)

// Defaults from §19.6/§19.5; both are configuration-sourced in production.
const (
	DefaultStartupTimeout = 5 * time.Minute
	DefaultShutdownGrace  = 5 * time.Second
)

type cancelTrigger int

const (
	triggerNone cancelTrigger = iota
	triggerStartupTimeout
	triggerPolicyTimeout
	triggerContext
	triggerChannelClosed
	triggerStream
)

// SuperviseOpts configures one Supervise call.
type SuperviseOpts struct {
	Ring           *StderrRing   // nil -> default-sized ring; stderr is always drained
	StartupTimeout time.Duration // <=0 -> DefaultStartupTimeout (§19.6 first-byte timer)
	PolicyTimeout  time.Duration // 0 -> no policy timeout
	Grace          time.Duration // <=0 -> DefaultShutdownGrace (§19.5 TERM->KILL ladder)
	Log            *slog.Logger  // nil -> discard
	// NewTimer overrides timer creation (injectable clock for tests). The
	// returned stop func releases the timer. nil -> time.NewTimer.
	NewTimer func(d time.Duration) (<-chan time.Time, func())
	// Observer receives tunnel lifecycle events. nil -> no-op.
	Observer Observer
}

// SupervisionResult reports how a supervised tunnel ended. Code is "" on
// clean completion, otherwise one of the core.TUNNEL_* audit detail codes.
type SupervisionResult struct {
	Code       string
	WaitErr    error // child Wait result; nil on exit 0
	FirstByte  bool  // first stdout byte observed (startup timer cancelled)
	StderrTail []byte
	Duration   time.Duration
}

func realTimer(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTimer(d)
	return t.C, func() { t.Stop() }
}

// Supervise runs the §19.5 supervision loop over a started child process and
// its outer channel: it drains stderr into the ring continuously (§19.7),
// runs both §19.3 copy loops, and selects over child exit, channel input
// closure, parent context cancellation, the §19.6 startup (first-byte)
// timeout, and an optional policy timeout.
//
// Cancellation follows the §19.5 ladder: close child stdin, SIGTERM the
// child's process GROUP, wait the grace interval, SIGKILL the group, then
// drain the single Wait result. Process.Wait is received exactly once.
// Supervise blocks until the tunnel ends and returns only after every
// goroutine it owns has finished.
func Supervise(ctx context.Context, proc *Process, channel ssh.Channel, opts SuperviseOpts) SupervisionResult {
	started := time.Now()
	log := opts.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	grace := opts.Grace
	if grace <= 0 {
		grace = DefaultShutdownGrace
	}
	startupTimeout := opts.StartupTimeout
	if startupTimeout <= 0 {
		startupTimeout = DefaultStartupTimeout
	}
	ring := opts.Ring
	if ring == nil {
		ring = NewStderrRing(0)
	}
	newTimer := opts.NewTimer
	if newTimer == nil {
		newTimer = realTimer
	}
	obs := opts.Observer
	if obs == nil {
		obs = NoopObserver{}
	}

	stderrDone := make(chan struct{})
	go func() {
		defer proc.StderrDrained()
		_, _ = io.Copy(ring, proc.Stderr)
		close(stderrDone)
	}()

	obs.ProcessStarted()
	px := startProxy(channel, proc, obs)

	startupC, stopStartup := newTimer(startupTimeout)
	defer stopStartup()
	var policyC <-chan time.Time
	if opts.PolicyTimeout > 0 {
		var stopPolicy func()
		policyC, stopPolicy = newTimer(opts.PolicyTimeout)
		defer stopPolicy()
	}

	waitCh := proc.Wait()
	upRes := px.upRes
	downRes := px.downRes
	firstByteC := px.firstByte
	firstByte := false
	var upErr, downErr error
	var lingerC <-chan time.Time
	var stopLinger func()

	var trigger cancelTrigger
	var waitErr error

	for waitCh != nil && trigger == triggerNone {
		select {
		case waitErr = <-waitCh:
			waitCh = nil
		case <-firstByteC:
			firstByteC = nil
			firstByte = true
			stopStartup()
			startupC = nil
		case <-startupC:
			trigger = triggerStartupTimeout
			startupC = nil
		case <-policyC:
			trigger = triggerPolicyTimeout
			policyC = nil
		case <-ctx.Done():
			trigger = triggerContext
		case err := <-upRes:
			upRes = nil
			upErr = err
			if err != nil {
				trigger = triggerStream
				continue
			}
			// Clean channel-input EOF (§19.3 half-close): the child now sees
			// stdin EOF and should exit on its own. If it does not within the
			// grace window the client is gone and the child is hung — cancel.
			lingerC, stopLinger = newTimer(grace)
		case err := <-downRes:
			downRes = nil
			downErr = err
			if err != nil {
				trigger = triggerStream
			}
		case <-lingerC:
			trigger = triggerChannelClosed
			lingerC = nil
		}
	}

	if trigger != triggerNone {
		waitErr = cancelChild(log, proc, channel, waitCh, grace, newTimer)
	}
	if stopLinger != nil {
		stopLinger()
	}

	// Unblock any copy loop still parked on the channel, then collect every
	// result so no goroutine outlives Supervise.
	_ = channel.Close()
	_ = proc.Stdin.Close()
	if upRes != nil {
		upErr = <-upRes
	}
	if downRes != nil {
		downErr = <-downRes
	}
	<-stderrDone

	res := SupervisionResult{
		FirstByte:  firstByte,
		WaitErr:    waitErr,
		StderrTail: ring.Tail(),
		Duration:   time.Since(started),
	}
	switch trigger {
	case triggerNone:
		switch {
		case !firstByte:
			res.Code = core.TUNNEL_CODER_EXITED
		case upErr != nil || downErr != nil:
			res.Code = core.TUNNEL_STREAM_FAILED
		}
	case triggerStartupTimeout:
		res.Code = core.TUNNEL_START_TIMEOUT
	case triggerStream:
		res.Code = core.TUNNEL_STREAM_FAILED
	default:
		res.Code = core.TUNNEL_CANCELLED
	}
	obs.ProcessExited(res.Code)
	obs.ActiveGauge(0)
	return res
}

// cancelChild runs the §19.5 cancellation ladder and returns the single Wait
// result. waitCh is guaranteed non-nil here: the trigger path is only taken
// before Wait fires.
func cancelChild(log *slog.Logger, proc *Process, channel ssh.Channel, waitCh <-chan error, grace time.Duration, newTimer func(time.Duration) (<-chan time.Time, func())) error {
	_ = proc.Stdin.Close()
	if err := syscall.Kill(-proc.PID, syscall.SIGTERM); err != nil {
		log.Debug("SIGTERM to process group failed",
			slog.Int("pid", proc.PID),
			slog.String("error", err.Error()),
		)
	}
	_ = channel.Close() // unblock copy loops parked on the channel

	graceC, stopGrace := newTimer(grace)
	defer stopGrace()
	select {
	case err := <-waitCh:
		return err
	case <-graceC:
		log.Debug("shutdown grace expired; SIGKILL to process group", slog.Int("pid", proc.PID))
		_ = syscall.Kill(-proc.PID, syscall.SIGKILL)
		return <-waitCh
	}
}
