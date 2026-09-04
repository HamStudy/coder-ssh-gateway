package audit

import (
	"log/slog"
	"testing"
)

func TestNewLoggerJSON(t *testing.T) {
	logger, err := NewLogger("json", "info")
	if err != nil {
		t.Fatalf("NewLogger(json, info) failed: %v", err)
	}
	if logger == nil {
		t.Fatal("logger is nil")
	}
}

func TestNewLoggerText(t *testing.T) {
	logger, err := NewLogger("text", "info")
	if err != nil {
		t.Fatalf("NewLogger(text, info) failed: %v", err)
	}
	if logger == nil {
		t.Fatal("logger is nil")
	}
}

func TestNewLoggerAllLevels(t *testing.T) {
	levels := []string{"debug", "info", "warn", "error"}
	for _, level := range levels {
		logger, err := NewLogger("json", level)
		if err != nil {
			t.Errorf("NewLogger(json, %s) failed: %v", level, err)
		}
		if logger == nil {
			t.Errorf("logger is nil for level %s", level)
		}
	}
}

func TestNewLoggerInvalidFormat(t *testing.T) {
	_, err := NewLogger("invalid", "info")
	if err == nil {
		t.Fatal("expected error for invalid format, got nil")
	}
	if err != ErrInvalidLogFormat {
		t.Errorf("expected ErrInvalidLogFormat, got %v", err)
	}
}

func TestNewLoggerInvalidLevel(t *testing.T) {
	_, err := NewLogger("json", "invalid")
	if err == nil {
		t.Fatal("expected error for invalid level, got nil")
	}
	if err != ErrInvalidLogLevel {
		t.Errorf("expected ErrInvalidLogLevel, got %v", err)
	}
}

func TestWithStdFields(t *testing.T) {
	logger, _ := NewLogger("json", "info")

	withFields := WithStdFields(logger, "conn-123", "deploy-456")

	if withFields == nil {
		t.Fatal("WithStdFields returned nil logger")
	}

	withFields.Info("test message")
}

func TestWithStdFieldsNil(t *testing.T) {
	result := WithStdFields(nil, "conn-123", "deploy-456")
	if result != nil {
		t.Error("WithStdFields should return nil for nil input")
	}
}

func TestLoggerWriteThrough(t *testing.T) {
	logger, _ := NewLogger("json", "info")
	withFields := WithStdFields(logger, "conn-123", "deploy-456")

	withFields.Info("test write through")
}

var _ = slog.Info
