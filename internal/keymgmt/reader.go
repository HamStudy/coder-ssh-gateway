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
// CR as well, because a pty client sends a bare CR for Enter. A CR
// immediately followed by LF counts as one terminator (CRLF).
type lineReader struct {
	src *bufio.Reader
	out io.Writer // receives the backspace erase echo in pty mode
	pty bool
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
		switch {
		case b == '\n' || b == '\r':
			if b == '\r' {
				// Collapse CRLF into one terminator.
				if next, err := r.src.Peek(1); err == nil && next[0] == '\n' {
					_, _ = r.src.Discard(1)
				}
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
		}
	}
}
