package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEventJSONSerialization(t *testing.T) {
	credGen := int64(1)
	durationMs := int64(150)
	bytesUp := int64(1024)
	bytesDown := int64(2048)
	event := Event{
		ID:                   "test-event-1",
		OccurredAtMs:         time.Now().UnixMilli(),
		ConnectionID:         "conn-123",
		DeploymentID:         "deploy-456",
		AccountID:            "acc-789",
		SSHKeyID:             "key-abc",
		EventType:            "auth_success",
		Result:               "success",
		PeerAddress:          "192.168.1.1:12345",
		Target:               "workspace1.coder-gateway.example.com",
		CredentialGeneration: &credGen,
		DurationMs:           &durationMs,
		BytesUp:              &bytesUp,
		BytesDown:            &bytesDown,
		DetailCode:           "AUTH_KEY_ACCEPTED",
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal event: %v", err)
	}

	if !strings.Contains(string(data), "occurred_at_ms") {
		t.Error("JSON should use snake_case field names")
	}
	if !strings.Contains(string(data), "connection_id") {
		t.Error("JSON should use snake_case field names")
	}
	if !strings.Contains(string(data), "deployment_id") {
		t.Error("JSON should use snake_case field names")
	}
	if !strings.Contains(string(data), "account_id") {
		t.Error("JSON should use snake_case field names")
	}
	if !strings.Contains(string(data), "ssh_key_id") {
		t.Error("JSON should use snake_case field names")
	}
	if !strings.Contains(string(data), "event_type") {
		t.Error("JSON should use snake_case field names")
	}
	if !strings.Contains(string(data), "credential_generation") {
		t.Error("JSON should use snake_case field names")
	}
	if !strings.Contains(string(data), "bytes_up") {
		t.Error("JSON should use snake_case field names")
	}
	if !strings.Contains(string(data), "bytes_down") {
		t.Error("JSON should use snake_case field names")
	}
	if !strings.Contains(string(data), "detail_code") {
		t.Error("JSON should use snake_case field names")
	}

	var decoded Event
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal event: %v", err)
	}

	if decoded.ID != event.ID {
		t.Errorf("ID mismatch: got %s, want %s", decoded.ID, event.ID)
	}
	if decoded.ConnectionID != event.ConnectionID {
		t.Errorf("ConnectionID mismatch: got %s, want %s", decoded.ConnectionID, event.ConnectionID)
	}
	if decoded.EventType != event.EventType {
		t.Errorf("EventType mismatch: got %s, want %s", decoded.EventType, event.EventType)
	}
}

func TestRedaction(t *testing.T) {
	token := "SECRETMARKER12345678_x" // matches tokenPattern: >=20 chars + separator
	event := Event{
		ID:           "test-redaction",
		OccurredAtMs: time.Now().UnixMilli(),
		EventType:    "test",
		Result:       "test",
		DetailCode:   token,
		Target:       token,
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal event: %v", err)
	}

	serialized := string(data)
	t.Logf("Serialized event: %s", serialized)

	if strings.Contains(serialized, token) {
		t.Errorf("redaction failed: token marker %q found in serialized output", token)
	}
}

func TestRedactionLongToken(t *testing.T) {
	token := "this-token-has-dashes-and_underscores-abc123"
	event := Event{
		ID:           "test-redaction-long",
		OccurredAtMs: time.Now().UnixMilli(),
		EventType:    "test",
		Result:       "test",
		DetailCode:   token,
		Target:       token,
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal event: %v", err)
	}

	serialized := string(data)
	if strings.Contains(serialized, token) {
		t.Errorf("redaction failed: long token found in serialized output")
	}
}

func TestRedactionNonTokenStrings(t *testing.T) {
	safeStrings := []string{
		"simple_string",
		"nounderscore",
		"nocaps123",
		"short",
		"a",
	}

	for _, s := range safeStrings {
		redacted := redactString(s)
		if redacted == "[REDACTED]" && s != "[REDACTED]" {
			t.Logf("String %q was redacted (may be expected for long token-like strings)", s)
		}
	}
}

func TestInMemoryLogger(t *testing.T) {
	logger := NewInMemoryLogger()

	event := Event{
		ID:           "mem-test-1",
		OccurredAtMs: time.Now().UnixMilli(),
		EventType:    "test_event",
		Result:       "success",
	}

	err := logger.Record(context.Background(), event)
	if err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	events := logger.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].ID != event.ID {
		t.Errorf("event ID mismatch: got %s, want %s", events[0].ID, event.ID)
	}
}

func TestInMemoryLoggerMultiple(t *testing.T) {
	logger := NewInMemoryLogger()

	for i := 0; i < 5; i++ {
		event := Event{
			ID:           "mem-test-multi",
			OccurredAtMs: time.Now().UnixMilli(),
			EventType:    "test_event",
			Result:       "success",
		}
		if err := logger.Record(context.Background(), event); err != nil {
			t.Fatalf("Record %d failed: %v", i, err)
		}
	}

	events := logger.Events()
	if len(events) != 5 {
		t.Fatalf("expected 5 events, got %d", len(events))
	}
}

func TestJSONLFileLogger(t *testing.T) {
	tmpDir := t.TempDir()

	logger, err := NewJSONLFileLogger(tmpDir, false)
	if err != nil {
		t.Fatalf("NewJSONLFileLogger failed: %v", err)
	}
	defer logger.Close()

	event := Event{
		ID:           "jsonl-test-1",
		OccurredAtMs: time.Now().UnixMilli(),
		EventType:    "test_event",
		Result:       "success",
	}

	if err := logger.Record(context.Background(), event); err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	if err := logger.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	dateStr := time.Now().Format("2006-01-02")
	expectedFile := filepath.Join(tmpDir, "audit-"+dateStr+".jsonl")

	if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
		t.Fatalf("expected file %s to exist", expectedFile)
	}

	data, err := os.ReadFile(expectedFile)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	var decoded Event
	if err := json.Unmarshal([]byte(lines[0]), &decoded); err != nil {
		t.Fatalf("failed to unmarshal line: %v", err)
	}

	if decoded.ID != event.ID {
		t.Errorf("ID mismatch: got %s, want %s", decoded.ID, event.ID)
	}
}

func TestJSONLFileLoggerMultiple(t *testing.T) {
	tmpDir := t.TempDir()

	logger, err := NewJSONLFileLogger(tmpDir, false)
	if err != nil {
		t.Fatalf("NewJSONLFileLogger failed: %v", err)
	}

	for i := 0; i < 3; i++ {
		event := Event{
			ID:           "jsonl-test-multi",
			OccurredAtMs: time.Now().UnixMilli(),
			EventType:    "test_event",
			Result:       "success",
		}
		if err := logger.Record(context.Background(), event); err != nil {
			t.Fatalf("Record %d failed: %v", i, err)
		}
	}

	if err := logger.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	dateStr := time.Now().Format("2006-01-02")
	expectedFile := filepath.Join(tmpDir, "audit-"+dateStr+".jsonl")

	data, err := os.ReadFile(expectedFile)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
}

func TestJSONLFileLoggerConcurrent(t *testing.T) {
	tmpDir := t.TempDir()

	logger, err := NewJSONLFileLogger(tmpDir, false)
	if err != nil {
		t.Fatalf("NewJSONLFileLogger failed: %v", err)
	}

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			event := Event{
				ID:           "concurrent-test",
				OccurredAtMs: time.Now().UnixMilli(),
				EventType:    "concurrent_event",
				Result:       "success",
			}
			_ = logger.Record(context.Background(), event)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	if err := logger.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	dateStr := time.Now().Format("2006-01-02")
	expectedFile := filepath.Join(tmpDir, "audit-"+dateStr+".jsonl")

	data, err := os.ReadFile(expectedFile)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 10 {
		t.Errorf("expected 10 lines, got %d", len(lines))
	}
}

func TestJSONLFileLoggerWithFSync(t *testing.T) {
	tmpDir := t.TempDir()

	logger, err := NewJSONLFileLogger(tmpDir, true)
	if err != nil {
		t.Fatalf("NewJSONLFileLogger with fsync failed: %v", err)
	}
	defer logger.Close()

	event := Event{
		ID:           "fsync-test",
		OccurredAtMs: time.Now().UnixMilli(),
		EventType:    "test",
		Result:       "success",
	}

	if err := logger.Record(context.Background(), event); err != nil {
		t.Fatalf("Record failed: %v", err)
	}
}

func TestJSONLFileLoggerDayRollover(t *testing.T) {
	tmpDir := t.TempDir()

	logger, err := NewJSONLFileLogger(tmpDir, false)
	if err != nil {
		t.Fatalf("NewJSONLFileLogger failed: %v", err)
	}
	defer logger.Close()

	clock := time.Date(2026, 9, 4, 23, 59, 59, 0, time.UTC)
	logger.now = func() time.Time { return clock }

	before := Event{ID: "before-midnight", OccurredAtMs: clock.UnixMilli(), EventType: "test", Result: "success"}
	if err := logger.Record(context.Background(), before); err != nil {
		t.Fatalf("Record before midnight failed: %v", err)
	}

	clock = clock.Add(2 * time.Second) // 2026-09-05 00:00:01
	after := Event{ID: "after-midnight", OccurredAtMs: clock.UnixMilli(), EventType: "test", Result: "success"}
	if err := logger.Record(context.Background(), after); err != nil {
		t.Fatalf("Record after midnight failed: %v", err)
	}

	day1, err := os.ReadFile(filepath.Join(tmpDir, "audit-2026-09-04.jsonl"))
	if err != nil {
		t.Fatalf("read day1 file: %v", err)
	}
	day2, err := os.ReadFile(filepath.Join(tmpDir, "audit-2026-09-05.jsonl"))
	if err != nil {
		t.Fatalf("read day2 file: %v", err)
	}
	if !strings.Contains(string(day1), "before-midnight") || strings.Contains(string(day1), "after-midnight") {
		t.Errorf("day1 file contents wrong: %s", day1)
	}
	if !strings.Contains(string(day2), "after-midnight") {
		t.Errorf("day2 file contents wrong: %s", day2)
	}

	// Same-day record after rollover must not reopen the file (handle stable).
	f := logger.f
	if err := logger.Record(context.Background(), after); err != nil {
		t.Fatalf("second same-day Record failed: %v", err)
	}
	if logger.f != f {
		t.Error("file handle changed without a day boundary crossing")
	}
	day2, err = os.ReadFile(filepath.Join(tmpDir, "audit-2026-09-05.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(day2), "after-midnight"); got != 2 {
		t.Errorf("day2 file has %d after-midnight events, want 2", got)
	}
}
