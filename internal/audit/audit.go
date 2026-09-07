package audit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{20,}[_-]+[A-Za-z0-9_-]*$|^[A-Za-z0-9_-]*[_-]+[A-Za-z0-9_-]{20,}$`)

func redactString(s string) string {
	if len(s) >= 20 && tokenPattern.MatchString(s) {
		return "[REDACTED]"
	}
	return s
}

type Event struct {
	ID                   string `json:"id"`
	OccurredAtMs         int64  `json:"occurred_at_ms"`
	ConnectionID         string `json:"connection_id,omitempty"`
	DeploymentID         string `json:"deployment_id,omitempty"`
	AccountID            string `json:"account_id,omitempty"`
	SSHKeyID             string `json:"ssh_key_id,omitempty"`
	EventType            string `json:"event_type"`
	Result               string `json:"result"`
	PeerAddress          string `json:"peer_address,omitempty"`
	Target               string `json:"target,omitempty"`
	CredentialGeneration *int64 `json:"credential_generation,omitempty"`
	DurationMs           *int64 `json:"duration_ms,omitempty"`
	BytesUp              *int64 `json:"bytes_up,omitempty"`
	BytesDown            *int64 `json:"bytes_down,omitempty"`
	DetailCode           string `json:"detail_code,omitempty"`
}

func (e Event) MarshalJSON() ([]byte, error) {
	type alias Event

	redacted := struct {
		alias
		DetailCode string `json:"detail_code,omitempty"`
		Target     string `json:"target,omitempty"`
	}{
		alias: alias(e),
	}

	redacted.DetailCode = redactString(e.DetailCode)
	redacted.Target = redactString(e.Target)

	return json.Marshal(redacted)
}

type Logger interface {
	Record(ctx context.Context, event Event) error
}

type InMemoryLogger struct {
	mu     sync.Mutex
	events []Event
}

func NewInMemoryLogger() *InMemoryLogger {
	return &InMemoryLogger{
		events: make([]Event, 0),
	}
}

func (l *InMemoryLogger) Record(ctx context.Context, event Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
	return nil
}

func (l *InMemoryLogger) Events() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	result := make([]Event, len(l.events))
	copy(result, l.events)
	return result
}

type JSONLFileLogger struct {
	mu      sync.Mutex
	dir     string
	f       *os.File
	fsync   bool
	dateStr string
	now     func() time.Time
}

// instanceSuffix disambiguates audit files when several gateway instances
// share one state directory (HA on NFS/Gluster/CephFS): explicit
// CSGW_AUDIT_INSTANCE, else the pod/machine HOSTNAME, else empty for the
// classic single-instance name.
func instanceSuffix() string {
	if v := os.Getenv("CSGW_AUDIT_INSTANCE"); v != "" {
		return sanitizeInstance(v)
	}
	if h := os.Getenv("HOSTNAME"); h != "" {
		return sanitizeInstance(h)
	}
	return ""
}

func sanitizeInstance(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := b.String()
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

func NewJSONLFileLogger(dir string, fsync bool) (*JSONLFileLogger, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	dateStr := time.Now().Format("2006-01-02")
	filename := auditFileName(dateStr)
	path := filepath.Join(dir, filename)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}

	return &JSONLFileLogger{
		dir:     dir,
		f:       f,
		fsync:   fsync,
		dateStr: dateStr,
		now:     time.Now,
	}, nil
}

// rollIfDayChangedLocked reopens the per-day file when the clock crosses
// midnight; on failure the old file stays open and the next Record retries.
func (l *JSONLFileLogger) rollIfDayChangedLocked() error {
	today := l.now().Format("2006-01-02")
	if today == l.dateStr {
		return nil
	}
	path := filepath.Join(l.dir, auditFileName(today))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := l.f.Close(); err != nil {
		f.Close()
		return err
	}
	l.f = f
	l.dateStr = today
	return nil
}

// auditFileName builds the per-day audit file name, including the instance
// suffix when one is configured.
func auditFileName(date string) string {
	name := "audit-" + date
	if suffix := instanceSuffix(); suffix != "" {
		name += "." + suffix
	}
	return name + ".jsonl"
}

func (l *JSONLFileLogger) Record(ctx context.Context, event Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.rollIfDayChangedLocked(); err != nil {
		return err
	}

	line := append(data, '\n')

	if _, err := l.f.Write(line); err != nil {
		return err
	}

	if l.fsync {
		if err := l.f.Sync(); err != nil {
			return err
		}
	}

	return nil
}

func (l *JSONLFileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

var (
	ErrInvalidLogFormat = errors.New("invalid log format: must be 'json' or 'text'")
	ErrInvalidLogLevel  = errors.New("invalid log level: must be 'debug', 'info', 'warn', or 'error'")
)
