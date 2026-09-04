package maintenance

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestSecretInputNoEcho(t *testing.T) {
	defer goleak.VerifyNone(t)
	reader, writer := io.Pipe()
	pump := newBytePump(reader)
	defer writer.Close()

	var echoed bytes.Buffer
	go func() {
		_, _ = writer.Write([]byte("s3cret-token\r"))
	}()
	line, err := pump.readLine(context.Background(), &echoed, 5*time.Second)
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if string(line) != "s3cret-token" {
		t.Fatalf("line = %q, want %q", line, "s3cret-token")
	}
	out := echoed.String()
	if out != "\r\n" {
		t.Fatalf("echoed output = %q, want only CRLF", out)
	}
	if strings.Contains(out, "s3cret") {
		t.Fatal("token characters were echoed")
	}
}

func TestSecretInputCRLFCompletion(t *testing.T) {
	defer goleak.VerifyNone(t)
	reader, writer := io.Pipe()
	pump := newBytePump(reader)
	defer writer.Close()

	var echoed bytes.Buffer
	go func() {
		_, _ = writer.Write([]byte("first\r\nsecond\n"))
	}()
	line, err := pump.readLine(context.Background(), &echoed, 5*time.Second)
	if err != nil || string(line) != "first" {
		t.Fatalf("first readLine = %q, %v", line, err)
	}
	// The LF of CRLF must be swallowed, not read as an empty second line.
	line, err = pump.readLine(context.Background(), &echoed, 5*time.Second)
	if err != nil || string(line) != "second" {
		t.Fatalf("second readLine = %q, %v", line, err)
	}
}

func TestSecretInputBackspace(t *testing.T) {
	defer goleak.VerifyNone(t)
	for _, erase := range []byte{byteDEL, byteBS} {
		reader, writer := io.Pipe()
		pump := newBytePump(reader)
		var echoed bytes.Buffer
		go func() {
			_, _ = writer.Write([]byte{'x', 'y', 'z', erase, '\r'})
		}()
		line, err := pump.readLine(context.Background(), &echoed, 5*time.Second)
		if err != nil {
			t.Fatalf("erase=%#x readLine: %v", erase, err)
		}
		if string(line) != "xy" {
			t.Fatalf("erase=%#x line = %q, want %q", erase, line, "xy")
		}
		writer.Close()
	}
}

func TestSecretInputCtrlCCancels(t *testing.T) {
	defer goleak.VerifyNone(t)
	reader, writer := io.Pipe()
	pump := newBytePump(reader)
	defer writer.Close()

	var echoed bytes.Buffer
	go func() {
		_, _ = writer.Write([]byte{'a', 'b', byteCtrlC})
	}()
	line, err := pump.readLine(context.Background(), &echoed, 5*time.Second)
	if !errors.Is(err, ErrInputCancelled) {
		t.Fatalf("err = %v, want ErrInputCancelled", err)
	}
	if line != nil {
		t.Fatalf("line = %q, want nil on cancel", line)
	}
}

func TestSecretInputLengthCap(t *testing.T) {
	defer goleak.VerifyNone(t)
	reader, writer := io.Pipe()
	pump := newBytePump(reader)
	defer writer.Close()

	var echoed bytes.Buffer
	go func() {
		_, _ = writer.Write([]byte(strings.Repeat("a", MaxSecretInputBytes+1)))
	}()
	_, err := pump.readLine(context.Background(), &echoed, 5*time.Second)
	if !errors.Is(err, ErrInputTooLong) {
		t.Fatalf("err = %v, want ErrInputTooLong", err)
	}
}

func TestSecretInputTimeout(t *testing.T) {
	defer goleak.VerifyNone(t)
	reader, writer := io.Pipe()
	pump := newBytePump(reader)
	defer writer.Close()

	var echoed bytes.Buffer
	start := time.Now()
	_, err := pump.readLine(context.Background(), &echoed, 60*time.Millisecond)
	if !errors.Is(err, ErrInputTimeout) {
		t.Fatalf("err = %v, want ErrInputTimeout", err)
	}
	if elapsed := time.Since(start); elapsed < 60*time.Millisecond {
		t.Fatalf("returned after %v, before the 60ms timeout", elapsed)
	}
}

func TestSecretInputTimeoutResetsPerKeystroke(t *testing.T) {
	defer goleak.VerifyNone(t)
	reader, writer := io.Pipe()
	pump := newBytePump(reader)
	defer writer.Close()

	var echoed bytes.Buffer
	go func() {
		for _, b := range []byte{'a', 'b', 'c', '\r'} {
			_, _ = writer.Write([]byte{b})
			time.Sleep(60 * time.Millisecond)
		}
	}()
	start := time.Now()
	line, err := pump.readLine(context.Background(), &echoed, 120*time.Millisecond)
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if string(line) != "abc" {
		t.Fatalf("line = %q, want %q", line, "abc")
	}
	// Total time (~240ms) exceeds the 120ms bound; per-keystroke gaps do not.
	if elapsed := time.Since(start); elapsed < 180*time.Millisecond {
		t.Fatalf("completed in %v; per-keystroke reset did not engage", elapsed)
	}
}

func TestSecretInputChannelClose(t *testing.T) {
	defer goleak.VerifyNone(t)
	reader, writer := io.Pipe()
	pump := newBytePump(reader)

	var echoed bytes.Buffer
	go func() {
		time.Sleep(30 * time.Millisecond)
		writer.Close()
	}()
	_, err := pump.readLine(context.Background(), &echoed, 5*time.Second)
	if !errors.Is(err, ErrInputClosed) {
		t.Fatalf("err = %v, want ErrInputClosed", err)
	}
}
