package app

import (
	"fmt"
	"strings"
)

// readSecret reads a secret line. With useStdin it reads a line from stdin;
// otherwise it reads from /dev/tty with echo disabled (§29: hidden TTY
// prompt or stdin). The prompt goes to stderr so stdout stays machine-clean.
func (c *cli) readSecret(prompt string, useStdin bool) ([]byte, error) {
	if useStdin {
		line, err := c.readLine()
		if err != nil {
			return nil, err
		}
		return []byte(line), nil
	}
	fmt.Fprint(c.stderr, prompt)
	line, err := readHiddenTTYLine()
	if err == nil {
		fmt.Fprintln(c.stderr)
		return []byte(line), nil
	}
	// No controlling terminal (piped script, CI): fall back to stdin.
	line, err = c.readLine()
	if err != nil {
		return nil, err
	}
	return []byte(line), nil
}

// confirm asks a yes/no question on the same channel the secret came from.
func (c *cli) confirm(prompt string, useStdin bool) (bool, error) {
	fmt.Fprint(c.stderr, prompt)
	var line string
	var err error
	if useStdin {
		line, err = c.readLine()
	} else {
		line, err = readTTYLine()
		if err != nil {
			line, err = c.readLine()
		}
	}
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(line), "yes"), nil
}
