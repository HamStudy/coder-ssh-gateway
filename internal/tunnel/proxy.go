package tunnel

import (
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
)

// proxyStreams owns the two §19.3 copy loops between the outer SSH channel
// and the child process pipes. Result channels are buffered(1) so a finished
// loop never blocks on a supervisor that already moved on.
type proxyStreams struct {
	upRes     chan error
	downRes   chan error
	firstByte chan struct{}
}

// startProxy launches the two copy directions:
//
//   - up: channel -> child stdin. Client EOF closes stdin but does NOT kill
//     the child (§19.3 half-close semantics).
//   - down: child stdout -> channel. The first buffer is read explicitly so
//     the §19.6 startup timer can be cancelled on the first byte (the start
//     of the inner SSH handshake); child stdout EOF then propagates to the
//     client as a channel EOF via CloseWrite.
func startProxy(channel ssh.Channel, proc *Process) *proxyStreams {
	px := &proxyStreams{
		upRes:     make(chan error, 1),
		downRes:   make(chan error, 1),
		firstByte: make(chan struct{}),
	}

	go func() {
		_, err := io.Copy(proc.Stdin, channel)
		closeErr := proc.Stdin.Close()
		px.upRes <- errors.Join(normalizeStreamErr(err), normalizeStreamErr(closeErr))
	}()

	go func() {
		buf := make([]byte, 32*1024)
		n, rerr := proc.Stdout.Read(buf)
		var werr error
		if n > 0 {
			close(px.firstByte)
			_, werr = channel.Write(buf[:n])
		}
		var copyErr error
		if rerr == nil && werr == nil {
			_, copyErr = io.Copy(channel, proc.Stdout)
		}
		closeErr := channel.CloseWrite()
		px.downRes <- errors.Join(
			normalizeStreamErr(rerr),
			normalizeStreamErr(werr),
			normalizeStreamErr(copyErr),
			normalizeStreamErr(closeErr),
		)
	}()

	return px
}

// normalizeStreamErr maps expected teardown conditions (EOF, closed channel
// or pipe, broken pipe, connection reset) to nil so supervision only reports
// actionable stream failures (§19.3).
func normalizeStreamErr(err error) error {
	switch {
	case err == nil,
		errors.Is(err, io.EOF),
		errors.Is(err, io.ErrClosedPipe),
		errors.Is(err, os.ErrClosed),
		errors.Is(err, syscall.EPIPE),
		errors.Is(err, syscall.ECONNRESET):
		return nil
	}
	if strings.Contains(err.Error(), "use of closed network connection") {
		return nil
	}
	return err
}
