package sshauth

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Covers every §38.1 token-sanitization bullet.
func TestSanitizeToken(t *testing.T) {
	t.Run("normal token", func(t *testing.T) {
		tok, err := SanitizeToken([]byte("abc123-DEF_456"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(tok) != "abc123-DEF_456" {
			t.Errorf("token = %q", tok)
		}
	})

	t.Run("CR LF from paste", func(t *testing.T) {
		tok, err := SanitizeToken([]byte("tok-en\r\n"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(tok) != "tok-en" {
			t.Errorf("token = %q", tok)
		}
	})

	t.Run("surrounding spaces and tabs", func(t *testing.T) {
		tok, err := SanitizeToken([]byte(" \t tok-en \t"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(tok) != "tok-en" {
			t.Errorf("token = %q", tok)
		}
	})

	t.Run("internal ASCII space accepted", func(t *testing.T) {
		// A plain space (0x20) is not a control character; only <0x20 bytes
		// are rejected. This test documents that decision.
		tok, err := SanitizeToken([]byte("tok en"))
		if err != nil {
			t.Fatalf("internal space rejected: %v", err)
		}
		if string(tok) != "tok en" {
			t.Errorf("token = %q", tok)
		}
	})

	t.Run("internal control characters rejected", func(t *testing.T) {
		for _, b := range []byte{0x00, 0x01, 0x07, 0x09, 0x0a, 0x0d, 0x1b, 0x1f} {
			if _, err := SanitizeToken([]byte{'a', b, 'b'}); !errors.Is(err, ErrTokenControlChar) {
				t.Errorf("byte %#x: err = %v, want ErrTokenControlChar", b, err)
			}
		}
	})

	t.Run("empty input", func(t *testing.T) {
		if _, err := SanitizeToken(nil); !errors.Is(err, ErrTokenEmpty) {
			t.Errorf("err = %v, want ErrTokenEmpty", err)
		}
	})

	t.Run("whitespace-only input is empty", func(t *testing.T) {
		if _, err := SanitizeToken([]byte("  \t\r\n ")); !errors.Is(err, ErrTokenEmpty) {
			t.Errorf("err = %v, want ErrTokenEmpty", err)
		}
	})

	t.Run("4096 byte boundary accepted", func(t *testing.T) {
		raw := bytes.Repeat([]byte("a"), MaxTokenBytes)
		tok, err := SanitizeToken(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tok) != MaxTokenBytes {
			t.Errorf("len = %d", len(tok))
		}
	})

	t.Run("4097 bytes overlong", func(t *testing.T) {
		raw := bytes.Repeat([]byte("a"), MaxTokenBytes+1)
		if _, err := SanitizeToken(raw); !errors.Is(err, ErrTokenTooLong) {
			t.Errorf("err = %v, want ErrTokenTooLong", err)
		}
	})

	t.Run("overlong after trimming", func(t *testing.T) {
		raw := append([]byte("  "), bytes.Repeat([]byte("a"), MaxTokenBytes+1)...)
		if _, err := SanitizeToken(raw); !errors.Is(err, ErrTokenTooLong) {
			t.Errorf("err = %v, want ErrTokenTooLong", err)
		}
	})

	t.Run("NUL inside token", func(t *testing.T) {
		if _, err := SanitizeToken([]byte("ab\x00cd")); !errors.Is(err, ErrTokenControlChar) {
			t.Errorf("err = %v, want ErrTokenControlChar", err)
		}
	})

	t.Run("invalid UTF-8 bytes accepted", func(t *testing.T) {
		// Tokens are byte strings; no UTF-8 validation is enforced (§13.2
		// forbids a brittle format regex). Only control bytes are rejected.
		tok, err := SanitizeToken([]byte{'a', 0xff, 0xfe, 'b'})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(tok, []byte{'a', 0xff, 0xfe, 'b'}) {
			t.Errorf("token = %q", tok)
		}
	})

	t.Run("error text never contains token bytes or length", func(t *testing.T) {
		marker := "ZZSECRETTOKENZZ"
		inputs := [][]byte{
			[]byte(""),
			[]byte(marker + "\x00"),
			bytes.Repeat([]byte(marker), 4096/len(marker)+2),
		}
		for _, in := range inputs {
			_, err := SanitizeToken(in)
			if err == nil {
				t.Fatalf("expected error for %q", in)
			}
			if strings.Contains(err.Error(), marker) {
				t.Errorf("error leaks token bytes: %q", err.Error())
			}
			if strings.ContainsAny(err.Error(), "0123456789") {
				t.Errorf("error leaks length: %q", err.Error())
			}
		}
	})

	t.Run("returned token does not alias input", func(t *testing.T) {
		raw := []byte("  token-value  ")
		tok, err := SanitizeToken(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		raw[2] = 'X'
		if string(tok) != "token-value" {
			t.Errorf("token mutated through input aliasing: %q", tok)
		}
	})
}
