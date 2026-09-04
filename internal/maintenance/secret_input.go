// Hidden line input over an ssh.Channel (§14.3): token characters are never
// echoed (the channel owns all output and input bytes are never written
// back), CR or LF completes the line, DEL/BS erase one byte, Ctrl-C cancels
// the session, and the line is capped at MaxSecretInputBytes. The inactivity
// timer is reset per keystroke.
package maintenance

import (
	"context"
	"errors"
	"io"
	"time"
)

// MaxSecretInputBytes is the §14.3 hidden-input line cap (matches
// sshauth.MaxTokenBytes so a capped line can never pass sanitization).
const MaxSecretInputBytes = 4096

var (
	// ErrInputCancelled marks Ctrl-C (0x03) at the prompt.
	ErrInputCancelled = errors.New("maintenance: input cancelled")
	// ErrInputTooLong marks input exceeding MaxSecretInputBytes.
	ErrInputTooLong = errors.New("maintenance: input exceeds length limit")
	// ErrInputTimeout marks the per-keystroke inactivity timeout.
	ErrInputTimeout = errors.New("maintenance: input timeout")
	// ErrInputClosed marks a channel that closed mid-input.
	ErrInputClosed = errors.New("maintenance: channel closed during input")
)

const (
	byteCtrlC = 0x03
	byteBS    = 0x08
	byteDEL   = 0x7f
)

type byteRead struct {
	b   byte
	err error
}

// bytePump decouples blocking channel reads from the timeout/select loop.
// One pump exists per session and exits when the channel closes. Sends are
// non-blocking against a buffer larger than the line cap, so the goroutine
// never outlives the session once the channel is closed.
type bytePump struct {
	reads  chan byteRead
	skipLF bool
}

func newBytePump(r io.Reader) *bytePump {
	p := &bytePump{reads: make(chan byteRead, 2*MaxSecretInputBytes)}
	go func() {
		one := make([]byte, 1)
		for {
			n, err := r.Read(one)
			if n > 0 {
				select {
				case p.reads <- byteRead{b: one[0]}:
				default:
				}
			}
			if err != nil {
				select {
				case p.reads <- byteRead{err: err}:
				default:
				}
				return
			}
		}
	}()
	return p
}

// readLine reads one hidden line: no byte is ever echoed to echoWriter; the
// only output written is the terminating CRLF (§14.3: "print only a newline
// after completion"). timeout is the inactivity bound, reset per keystroke.
// The returned buffer is caller-owned secret material; callers wipe it.
func (p *bytePump) readLine(ctx context.Context, echoWriter io.Writer, timeout time.Duration) ([]byte, error) {
	var line []byte
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	reset := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(timeout)
	}
	for {
		select {
		case rb := <-p.reads:
			if rb.err != nil {
				return nil, ErrInputClosed
			}
			reset()
			b := rb.b
			if p.skipLF {
				p.skipLF = false
				if b == '\n' {
					continue
				}
			}
			switch b {
			case byteCtrlC:
				_, _ = io.WriteString(echoWriter, "\r\n")
				return nil, ErrInputCancelled
			case '\r':
				p.skipLF = true
				_, _ = io.WriteString(echoWriter, "\r\n")
				return line, nil
			case '\n':
				_, _ = io.WriteString(echoWriter, "\r\n")
				return line, nil
			case byteDEL, byteBS:
				if len(line) > 0 {
					line = line[:len(line)-1]
				}
			default:
				if len(line) >= MaxSecretInputBytes {
					_, _ = io.WriteString(echoWriter, "\r\n")
					return nil, ErrInputTooLong
				}
				line = append(line, b)
			}
		case <-timer.C:
			return nil, ErrInputTimeout
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
