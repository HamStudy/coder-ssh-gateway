package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/core"
	"github.com/taxilian/coder-ssh-gateway/internal/testleaks"
	"github.com/taxilian/coder-ssh-gateway/internal/testutil"
	"github.com/taxilian/coder-ssh-gateway/internal/testutil/innerssh"
)

// fakeChannel is a minimal in-test ssh.Channel over two OS pipe pairs
// (kernel-buffered, real EOF semantics — see T10 learnings). The test holds
// the client ends (clientR reads server->client, clientW writes
// client->server) and can half-close or abruptly close them independently.
type fakeChannel struct {
	r      *os.File // server side reads client -> server
	w      *os.File // server side writes server -> client
	stderr bytes.Buffer

	mu       sync.Mutex
	closed   bool
	cwClosed bool
}

var _ ssh.Channel = (*fakeChannel)(nil)

func newFakeChannel(t *testing.T) (ch *fakeChannel, clientR, clientW *os.File) {
	t.Helper()
	c2sR, c2sW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe c2s: %v", err)
	}
	s2cR, s2cW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe s2c: %v", err)
	}
	return &fakeChannel{r: c2sR, w: s2cW}, s2cR, c2sW
}

func (f *fakeChannel) Read(p []byte) (int, error) { return f.r.Read(p) }

func (f *fakeChannel) Write(p []byte) (int, error) {
	f.mu.Lock()
	dead := f.closed || f.cwClosed
	f.mu.Unlock()
	if dead {
		return 0, io.ErrClosedPipe
	}
	return f.w.Write(p)
}

func (f *fakeChannel) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	_ = f.r.Close()
	_ = f.w.Close()
	return nil
}

func (f *fakeChannel) CloseWrite() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cwClosed {
		return nil
	}
	f.cwClosed = true
	if f.closed {
		return nil // w already closed by Close
	}
	return f.w.Close()
}

func (f *fakeChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, nil
}

func (f *fakeChannel) Stderr() io.ReadWriter { return &f.stderr }

func (f *fakeChannel) IsClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// spawnFakeProcess starts the T10 fake coder binary with the given
// FAKE_CODER_* knobs and wraps it in a Process with an exactly-once Wait
// channel (mirroring Launcher.Launch; the send counter lets tests assert
// the Wait producer fired exactly once).
func spawnFakeProcess(t *testing.T, knobs ...string) (*Process, *atomic.Int32) {
	t.Helper()
	bin := testutil.BuildFakeCoder(t)
	args := testutil.FakeArgv(t.TempDir(), "auto", "w", false)
	env := append(testutil.FakeEnv("test-token-supervise"), knobs...)
	cmd := testutil.NewFakeCmd(t, bin, env, args...)
	cmd.Dir = t.TempDir()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	sends := &atomic.Int32{}
	proc := &Process{
		Cmd:       cmd,
		PID:       cmd.Process.Pid,
		Stdin:     stdin,
		Stdout:    stdout,
		Stderr:    stderr,
		StartedAt: time.Now(),
		waitCh:    make(chan error, 1),
	}
	proc.drains.Add(2) // stdout + stderr consumers, mirroring Launcher.Launch
	go func() {
		proc.drains.Wait()
		err := cmd.Wait()
		sends.Add(1)
		proc.waitCh <- err
	}()
	return proc, sends
}

func fastSuperviseOpts() SuperviseOpts {
	return SuperviseOpts{
		StartupTimeout: 5 * time.Second,
		Grace:          500 * time.Millisecond,
	}
}

func runSupervise(ctx context.Context, proc *Process, ch *fakeChannel, opts SuperviseOpts) <-chan SupervisionResult {
	done := make(chan SupervisionResult, 1)
	go func() { done <- Supervise(ctx, proc, ch, opts) }()
	return done
}

func recvResult(t *testing.T, done <-chan SupervisionResult, timeout time.Duration) SupervisionResult {
	t.Helper()
	select {
	case res := <-done:
		return res
	case <-time.After(timeout):
		t.Fatal("Supervise did not return in time")
		panic("unreachable")
	}
}

// procState returns the process state byte from /proc/<pid>/stat (the field
// right after the comm parenthesis, which may itself contain spaces/parens).
func procState(pid int) (byte, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	i := bytes.LastIndexByte(data, ')')
	if i < 0 || i+2 >= len(data) {
		return 0, false
	}
	return data[i+2], true
}

// procGone reports whether the pid has no live /proc entry. Zombies count as
// gone: a re-parented grandchild is reaped asynchronously by init.
func procGone(pid int) bool {
	st, ok := procState(pid)
	return !ok || st == 'Z'
}

func waitProcGone(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if procGone(pid) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return procGone(pid)
}

// childPidsOf scans /proc for direct children of ppid.
func childPidsOf(ppid int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		i := bytes.LastIndexByte(data, ')')
		if i < 0 {
			continue
		}
		fields := strings.Fields(string(data[i+1:]))
		if len(fields) < 2 {
			continue
		}
		p, err := strconv.Atoi(fields[1]) // fields[0]=state, fields[1]=ppid
		if err == nil && p == ppid {
			out = append(out, pid)
		}
	}
	return out
}

// §38.1: child exits before stdout -> TUNNEL_CODER_EXITED, stderr ring holds
// the diagnostic, Wait drained exactly once, and no stderr byte ever reaches
// the channel (§18.5).
func TestSuperviseChildExitsBeforeStdout(t *testing.T) {
	defer testleaks.Verify(t)

	proc, sends := spawnFakeProcess(t,
		"FAKE_CODER_STDERR=boom: workspace exploded",
		"FAKE_CODER_EXIT_AFTER_MS=100",
		"FAKE_CODER_EXIT_CODE=70",
	)
	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()
	defer clientW.Close()

	res := Supervise(context.Background(), proc, ch, fastSuperviseOpts())

	if res.Code != core.TUNNEL_CODER_EXITED {
		t.Errorf("Code = %q, want %q", res.Code, core.TUNNEL_CODER_EXITED)
	}
	if res.FirstByte {
		t.Error("FirstByte = true, want false (child never wrote stdout)")
	}
	if !strings.Contains(string(res.StderrTail), "workspace exploded") {
		t.Errorf("StderrTail = %q, want it to contain the diagnostic", res.StderrTail)
	}
	if got := sends.Load(); got != 1 {
		t.Errorf("Wait producer sends = %d, want exactly 1", got)
	}
	select {
	case <-proc.Wait():
		t.Error("Wait() delivered a second result after Supervise returned")
	case <-time.After(100 * time.Millisecond):
	}

	// §18.5: stderr must never be merged into the protocol channel. The
	// channel saw zero payload bytes (only the supervisor's close => EOF).
	readCh := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		buf := make([]byte, 64)
		n, err := clientR.Read(buf)
		readCh <- struct {
			n   int
			err error
		}{n, err}
	}()
	select {
	case rr := <-readCh:
		if rr.n != 0 || rr.err != io.EOF {
			t.Errorf("channel read = (%d, %v), want (0, EOF) — no stderr may leak into the channel", rr.n, rr.err)
		}
	case <-time.After(2 * time.Second):
		t.Error("client read did not observe channel EOF after child exit")
	}
}

// §38.1: child emits stderr only + first-byte timeout. Stderr activity must
// NOT reset the §19.6 startup timer.
func TestSuperviseFirstByteTimeout(t *testing.T) {
	defer testleaks.Verify(t)

	proc, _ := spawnFakeProcess(t,
		"FAKE_CODER_STDERR=spam spam spam spam",
		"FAKE_CODER_NO_STDOUT=1",
	)
	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()
	defer clientW.Close()

	start := time.Now()
	res := Supervise(context.Background(), proc, ch, SuperviseOpts{
		StartupTimeout: 500 * time.Millisecond,
		Grace:          200 * time.Millisecond,
	})
	elapsed := time.Since(start)

	if res.Code != core.TUNNEL_START_TIMEOUT {
		t.Errorf("Code = %q, want %q", res.Code, core.TUNNEL_START_TIMEOUT)
	}
	if res.FirstByte {
		t.Error("FirstByte = true, want false")
	}
	if elapsed < 450*time.Millisecond {
		t.Errorf("timeout fired after %v (< 500ms) — stderr spam must not reset the startup timer", elapsed)
	}
	if !waitProcGone(proc.PID, 2*time.Second) {
		t.Error("child still present in /proc after startup-timeout cancellation")
	}
}

// §38.1: full duplex — a real x/crypto SSH client round-trips through the
// proxy into the fake's inner SSH server (both copy loops exercised).
func TestSuperviseFullDuplex(t *testing.T) {
	defer testleaks.Verify(t)

	proc, _ := spawnFakeProcess(t)
	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()

	done := runSupervise(context.Background(), proc, ch, fastSuperviseOpts())

	conn, chans, reqs, err := ssh.NewClientConn(
		innerssh.NewConn(clientR, clientW),
		"pipe",
		&ssh.ClientConfig{
			User:            "test",
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("inner handshake through proxy: %v", err)
	}
	client := ssh.NewClient(conn, chans, reqs)

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	out, err := session.Output("hello")
	if err != nil {
		t.Fatalf("exec through proxy: %v", err)
	}
	if string(out) != "ECHO:hello" {
		t.Fatalf("exec output = %q, want %q", out, "ECHO:hello")
	}
	_ = session.Close()

	// Clean client disconnect (T10 gotcha: close client conn AND stdin side).
	_ = client.Close()
	_ = clientW.Close()

	res := recvResult(t, done, 5*time.Second)
	if res.Code != "" {
		t.Errorf("Code = %q, want success (\"\")", res.Code)
	}
	if !res.FirstByte {
		t.Error("FirstByte = false, want true (inner SSH banner flowed)")
	}
	if res.WaitErr != nil {
		t.Errorf("WaitErr = %v, want nil (fake exits 0 on clean disconnect)", res.WaitErr)
	}
}

// §38.1: half-close client->child. Client EOF closes child stdin but must
// NOT kill the child; the child exits on its own when it sees stdin EOF.
func TestSuperviseHalfCloseClientEOF(t *testing.T) {
	defer testleaks.Verify(t)

	proc, _ := spawnFakeProcess(t)
	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()

	done := runSupervise(context.Background(), proc, ch, SuperviseOpts{
		StartupTimeout: 5 * time.Second,
		Grace:          2 * time.Second,
	})

	// Complete the inner handshake so the first byte has flowed.
	conn, chans, reqs, err := ssh.NewClientConn(
		innerssh.NewConn(clientR, clientW),
		"pipe",
		&ssh.ClientConfig{
			User:            "test",
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("inner handshake: %v", err)
	}
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()

	start := time.Now()
	_ = clientW.Close() // half-close: EOF towards child stdin, keep reading

	res := recvResult(t, done, 5*time.Second)
	elapsed := time.Since(start)
	if res.Code != "" {
		t.Errorf("Code = %q, want success — child should exit on stdin EOF, not be killed", res.Code)
	}
	if !res.FirstByte {
		t.Error("FirstByte = false, want true")
	}
	if elapsed >= 2*time.Second {
		t.Errorf("child took %v (>= grace) to exit after stdin EOF — supervisor killed a well-behaved child", elapsed)
	}
	if res.WaitErr != nil {
		t.Errorf("WaitErr = %v, want nil (clean exit 0 on disconnect)", res.WaitErr)
	}
}

// §38.1: half-close child->client. Child stdout EOF must propagate to the
// client as a channel EOF (CloseWrite) while the child exit is supervised.
func TestSuperviseHalfCloseChildEOF(t *testing.T) {
	defer testleaks.Verify(t)

	proc, _ := spawnFakeProcess(t,
		"FAKE_CODER_EXIT_AFTER_MS=150",
		"FAKE_CODER_EXIT_CODE=0",
	)
	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()
	defer clientW.Close()

	done := runSupervise(context.Background(), proc, ch, fastSuperviseOpts())

	// The client must observe channel EOF once the child's stdout closes.
	eofCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := clientR.Read(buf)
		eofCh <- err
	}()
	select {
	case err := <-eofCh:
		if err != io.EOF {
			t.Errorf("client read err = %v, want io.EOF (channel EOF after child stdout closed)", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("client never observed channel EOF after child exit")
	}

	res := recvResult(t, done, 5*time.Second)
	if res.Code != core.TUNNEL_CODER_EXITED {
		t.Errorf("Code = %q, want %q (child exited before any stdout byte)", res.Code, core.TUNNEL_CODER_EXITED)
	}
}

// §38.1: abrupt client close. The channel EOF reaches the up copy loop, but
// a child that ignores stdin EOF must still be cancelled within grace —
// supervision must not hang on a hung child after the client is gone.
func TestSuperviseAbruptClientClose(t *testing.T) {
	defer testleaks.Verify(t)

	proc, _ := spawnFakeProcess(t, "FAKE_CODER_NO_STDOUT=1")
	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()

	done := runSupervise(context.Background(), proc, ch, SuperviseOpts{
		StartupTimeout: 10 * time.Second,
		Grace:          400 * time.Millisecond,
	})

	time.Sleep(150 * time.Millisecond) // let the copy loops park on the pipes
	start := time.Now()
	_ = clientW.Close() // abrupt: channel read EOF while child blocks forever

	res := recvResult(t, done, 5*time.Second)
	elapsed := time.Since(start)
	if res.Code != core.TUNNEL_CANCELLED {
		t.Errorf("Code = %q, want %q", res.Code, core.TUNNEL_CANCELLED)
	}
	if elapsed < 300*time.Millisecond {
		t.Errorf("cancelled after %v (< linger grace 400ms) — half-close semantics violated", elapsed)
	}
	if !waitProcGone(proc.PID, 2*time.Second) {
		t.Error("child still present in /proc after abrupt-close cancellation")
	}
}

// §38.1: server shutdown — parent ctx cancellation cancels the child and
// reports TUNNEL_CANCELLED.
func TestSuperviseServerShutdown(t *testing.T) {
	defer testleaks.Verify(t)

	proc, _ := spawnFakeProcess(t, "FAKE_CODER_NO_STDOUT=1")
	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()
	defer clientW.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := runSupervise(ctx, proc, ch, SuperviseOpts{
		StartupTimeout: 10 * time.Second,
		Grace:          1 * time.Second,
	})

	time.Sleep(150 * time.Millisecond)
	cancel()

	res := recvResult(t, done, 5*time.Second)
	if res.Code != core.TUNNEL_CANCELLED {
		t.Errorf("Code = %q, want %q", res.Code, core.TUNNEL_CANCELLED)
	}
	if !waitProcGone(proc.PID, 2*time.Second) {
		t.Error("child still present in /proc after shutdown cancellation")
	}
}

// §38.1: TERM then exit — a cooperative child dies on SIGTERM; SIGKILL must
// not be needed (Wait returns well before the grace expires).
func TestSuperviseTermThenExit(t *testing.T) {
	defer testleaks.Verify(t)

	proc, _ := spawnFakeProcess(t, "FAKE_CODER_NO_STDOUT=1")
	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()
	defer clientW.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := runSupervise(ctx, proc, ch, SuperviseOpts{
		StartupTimeout: 10 * time.Second,
		Grace:          2 * time.Second,
	})

	time.Sleep(150 * time.Millisecond)
	start := time.Now()
	cancel()

	res := recvResult(t, done, 5*time.Second)
	elapsed := time.Since(start)
	if res.Code != core.TUNNEL_CANCELLED {
		t.Errorf("Code = %q, want %q", res.Code, core.TUNNEL_CANCELLED)
	}
	if elapsed >= 1500*time.Millisecond {
		t.Errorf("Wait returned after %v (~grace) — SIGTERM should have sufficed, no SIGKILL expected", elapsed)
	}
	if res.WaitErr == nil || !strings.Contains(res.WaitErr.Error(), "terminated") {
		t.Errorf("WaitErr = %v, want SIGTERM termination", res.WaitErr)
	}
}

// §38.1: TERM ignored then KILL — the fake traps SIGTERM; after the grace
// interval the supervisor must SIGKILL the process group and reap.
func TestSuperviseTermIgnoredThenKill(t *testing.T) {
	defer testleaks.Verify(t)

	proc, _ := spawnFakeProcess(t,
		"FAKE_CODER_IGNORE_SIGTERM=1",
		"FAKE_CODER_NO_STDOUT=1",
	)
	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()
	defer clientW.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := runSupervise(ctx, proc, ch, SuperviseOpts{
		StartupTimeout: 10 * time.Second,
		Grace:          300 * time.Millisecond,
	})

	time.Sleep(150 * time.Millisecond)
	start := time.Now()
	cancel()

	res := recvResult(t, done, 5*time.Second)
	elapsed := time.Since(start)
	if res.Code != core.TUNNEL_CANCELLED {
		t.Errorf("Code = %q, want %q", res.Code, core.TUNNEL_CANCELLED)
	}
	if elapsed < 280*time.Millisecond {
		t.Errorf("SIGKILL sent after %v (< grace 300ms) — grace interval not honored", elapsed)
	}
	if res.WaitErr == nil || !strings.Contains(res.WaitErr.Error(), "killed") {
		t.Errorf("WaitErr = %v, want SIGKILL termination", res.WaitErr)
	}
	if !waitProcGone(proc.PID, 2*time.Second) {
		t.Error("child still present in /proc after SIGKILL")
	}
}

// §38.1: descendant cleanup — the fake spawns a grandchild in its process
// group; the group signal must reap it when supervision ends.
func TestSuperviseDescendantCleanup(t *testing.T) {
	defer testleaks.Verify(t)

	proc, _ := spawnFakeProcess(t,
		"FAKE_CODER_SPAWN_CHILD=1",
		"FAKE_CODER_NO_STDOUT=1",
	)
	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()
	defer clientW.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := runSupervise(ctx, proc, ch, SuperviseOpts{
		StartupTimeout: 10 * time.Second,
		Grace:          1 * time.Second,
	})

	var grandchildren []int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		grandchildren = childPidsOf(proc.PID)
		if len(grandchildren) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(grandchildren) == 0 {
		t.Fatal("grandchild never appeared under the fake child")
	}

	cancel()
	res := recvResult(t, done, 5*time.Second)
	if res.Code != core.TUNNEL_CANCELLED {
		t.Errorf("Code = %q, want %q", res.Code, core.TUNNEL_CANCELLED)
	}
	if !waitProcGone(proc.PID, 2*time.Second) {
		t.Error("child still present in /proc after group cancellation")
	}
	for _, g := range grandchildren {
		if !waitProcGone(g, 3*time.Second) {
			t.Errorf("grandchild pid %d still alive after process-group kill", g)
		}
	}
}

// §38.1: optional policy timeout cancels a running tunnel.
func TestSupervisePolicyTimeout(t *testing.T) {
	defer testleaks.Verify(t)

	proc, _ := spawnFakeProcess(t, "FAKE_CODER_NO_STDOUT=1")
	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()
	defer clientW.Close()

	start := time.Now()
	res := Supervise(context.Background(), proc, ch, SuperviseOpts{
		StartupTimeout: 10 * time.Second,
		PolicyTimeout:  300 * time.Millisecond,
		Grace:          200 * time.Millisecond,
	})
	elapsed := time.Since(start)
	if res.Code != core.TUNNEL_CANCELLED {
		t.Errorf("Code = %q, want %q", res.Code, core.TUNNEL_CANCELLED)
	}
	if elapsed < 250*time.Millisecond || elapsed > 3*time.Second {
		t.Errorf("policy timeout fired after %v, want ~300ms", elapsed)
	}
}

// §38.1: bounded stderr ring — child writes more than the cap; the ring
// keeps exactly the LAST cap bytes.
func TestSuperviseStderrRingBound(t *testing.T) {
	defer testleaks.Verify(t)

	big := strings.Repeat("x", 32*1024)
	proc, _ := spawnFakeProcess(t,
		"FAKE_CODER_STDERR="+big,
		"FAKE_CODER_EXIT_AFTER_MS=150",
		"FAKE_CODER_EXIT_CODE=3",
	)
	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()
	defer clientW.Close()

	ring := NewStderrRing(1024)
	res := Supervise(context.Background(), proc, ch, SuperviseOpts{
		Ring:           ring,
		StartupTimeout: 5 * time.Second,
		Grace:          500 * time.Millisecond,
	})
	if res.Code != core.TUNNEL_CODER_EXITED {
		t.Errorf("Code = %q, want %q", res.Code, core.TUNNEL_CODER_EXITED)
	}
	if len(res.StderrTail) != 1024 {
		t.Fatalf("StderrTail length = %d, want exactly 1024", len(res.StderrTail))
	}
	want := strings.Repeat("x", 1023) + "\n"
	if string(res.StderrTail) != want {
		t.Errorf("StderrTail is not the LAST 1024 bytes of the child's stderr")
	}
}

// §38.1: Wait is drained exactly once even on the cancellation path.
func TestSuperviseWaitExactlyOnce(t *testing.T) {
	defer testleaks.Verify(t)

	proc, sends := spawnFakeProcess(t)
	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()
	defer clientW.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := runSupervise(ctx, proc, ch, fastSuperviseOpts())

	time.Sleep(150 * time.Millisecond)
	cancel()
	_ = recvResult(t, done, 5*time.Second)

	if got := sends.Load(); got != 1 {
		t.Errorf("Wait producer sends = %d, want exactly 1", got)
	}
	select {
	case <-proc.Wait():
		t.Error("Wait() delivered a second result — supervisor did not drain exactly once")
	case <-time.After(100 * time.Millisecond):
	}
}
