package sshauth

import (
	"bytes"
	"errors"
)

// MaxTokenBytes is the maximum accepted token length after trimming (§13.2).
const MaxTokenBytes = 4096

// tokenCutset is the ASCII whitespace trimmed from both ends of a pasted
// token: space, tab, CR, LF (§13.2 copy/paste hygiene).
const tokenCutset = " \t\r\n"

var (
	// ErrTokenEmpty rejects input that is empty after trimming.
	ErrTokenEmpty = errors.New("token is empty")
	// ErrTokenTooLong rejects input exceeding MaxTokenBytes after trimming.
	ErrTokenTooLong = errors.New("token is too long")
	// ErrTokenControlChar rejects NUL and other control characters inside
	// the token (§13.2).
	ErrTokenControlChar = errors.New("token contains a forbidden control character")
)

// SanitizeToken normalizes a candidate Coder token entered at a
// keyboard-interactive or password prompt (§13.2).
//
// Leading and trailing ASCII whitespace introduced by copy/paste is trimmed.
// NUL and all control characters below 0x20 inside the token are rejected;
// ordinary internal spaces (0x20, not a control character) are accepted —
// no brittle token-format regex is enforced. The post-trim length is bounded
// at MaxTokenBytes.
//
// Error values are static sentinels: they never contain token bytes or the
// token length (§13.2, §35).
func SanitizeToken(raw []byte) ([]byte, error) {
	trimmed := bytes.Trim(raw, tokenCutset)
	if len(trimmed) == 0 {
		return nil, ErrTokenEmpty
	}
	if len(trimmed) > MaxTokenBytes {
		return nil, ErrTokenTooLong
	}
	for _, b := range trimmed {
		if b < 0x20 {
			return nil, ErrTokenControlChar
		}
	}
	return bytes.Clone(trimmed), nil
}
