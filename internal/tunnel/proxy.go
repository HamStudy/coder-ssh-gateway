package tunnel

import (
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
)

type proxyStreams struct {
	upRes     chan error
	downRes   chan error
	firstByte chan struct{}
}

func startProxy(channel ssh.Channel, proc *Process, obs Observer) *proxyStreams {
	px := &proxyStreams{
		upRes:     make(chan error, 1),
		downRes:   make(chan error, 1),
		firstByte: make(chan struct{}),
	}

	if obs == nil {
		obs = NoopObserver{}
	}

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := channel.Read(buf)
			if n > 0 {
				obs.TunnelBytes("up", n)
				if _, werr := proc.Stdin.Write(buf[:n]); werr != nil {
					px.upRes <- err
					return
				}
			}
			if err != nil {
				closeErr := proc.Stdin.Close()
				px.upRes <- errors.Join(normalizeStreamErr(err), normalizeStreamErr(closeErr))
				return
			}
		}
	}()

	go func() {
		buf := make([]byte, 32*1024)
		n, rerr := proc.Stdout.Read(buf)
		var werr error
		if n > 0 {
			close(px.firstByte)
			obs.TunnelBytes("down", n)
			_, werr = channel.Write(buf[:n])
		}
		var copyErr error
		if rerr == nil && werr == nil {
			for {
				n, err := proc.Stdout.Read(buf)
				if n > 0 {
					obs.TunnelBytes("down", n)
					if _, werr := channel.Write(buf[:n]); werr != nil {
						break
					}
				}
				if err != nil {
					break
				}
			}
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
