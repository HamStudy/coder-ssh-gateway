package keymgmt

import (
	"bufio"
	"errors"
	"io"
)

// maxLineBytes caps one input line, excluding the terminator. Longer input
// is discarded up to the terminator and reported as errOverlong.
const maxLineBytes = 256

// errOverlong marks a line that exceeded maxLineBytes.
var errOverlong = errors.New("input line too long")

// lineReader reads user input lines byte-by-byte so pty line-editing bytes
// (backspace) can be handled before line assembly. Terminators: LF always;
// CR too, IMMEDIATELY — a real pty client sends a bare CR for Enter and no
// byte may follow for a long time, so the reader never waits after a CR.
// CRLF still counts as one terminator: the CR sets a pending-LF flag and the
// next byte read — in whatever later readLine call — is discarded when it is
// an LF. In pty mode every printable-ASCII byte appended to the line is
// echoed to out so the user sees what they type; backspace erases with a
// "\b \b" echo. No-pty mode is byte-for-byte pass-through with no echo.
type lineReader struct {
	src *bufio.Reader
	out io.Writer // receives the echo in pty mode
	pty bool
	// pendingLF is set by a CR terminator; the next byte read, if LF, is
	// swallowed so CRLF is one terminator rather than line + empty line.
	pendingLF bool
}

func newLineReader(in io.Reader, out io.Writer, pty bool) *lineReader {
	return &lineReader{src: bufio.NewReader(in), out: out, pty: pty}
}

// readLine returns the next line without its terminator, io.EOF at end of
// input, errOverlong when the line exceeded the cap, or the underlying
// reader error. A final unterminated line (EOF with pending bytes) is
// returned as a line.
func (r *lineReader) readLine() (string, error) {
	var buf []byte
	overlong := false
	for {
		b, err := r.src.ReadByte()
		if err == io.EOF {
			if overlong {
				return "", errOverlong
			}
			if len(buf) > 0 {
				return string(buf), nil
			}
			return "", io.EOF
		}
		if err != nil {
			return "", err
		}
		if r.pendingLF {
			r.pendingLF = false
			if b == '\n' {
				continue
			}
		}
		switch {
		case b == '\n' || b == '\r':
			if b == '\r' {
				r.pendingLF = true
			}
			if overlong {
				return "", errOverlong
			}
			return string(buf), nil
		case overlong:
			// Discard bytes until the terminator.
		case r.pty && (b == 0x7f || b == 0x08):
			// Erase the last pending byte; echo the erase sequence so a
			// pty client's display tracks the edit. Nothing to erase yet
			// means the backspace itself is dropped silently.
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				_, _ = r.out.Write([]byte("\b \b"))
			}
		case len(buf) >= maxLineBytes:
			overlong = true
		default:
			buf = append(buf, b)
			if r.pty && b >= 0x20 && b <= 0x7e {
				_, _ = r.out.Write([]byte{b})
			}
		}
	}
}
