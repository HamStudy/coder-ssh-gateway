package app

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// auditFilePrefix/auditFileExt frame the per-day audit file names produced
// by audit.JSONLFileLogger (audit-YYYY-MM-DD.jsonl).
const (
	auditFilePrefix = "audit-"
	auditFileExt    = ".jsonl"
)

// PruneAuditFiles deletes daily audit JSONL files older than retentionDays
// relative to now. The file date is parsed from the name; files that do not
// match the naming scheme are never touched. Returns the deleted paths.
// retentionDays <= 0 disables pruning (caller should not run the job).
func PruneAuditFiles(dir string, retentionDays int, now time.Time, log *slog.Logger) ([]string, error) {
	if log == nil {
		log = slog.Default()
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	cutoff := midnightUTC(now).AddDate(0, 0, -retentionDays)
	var deleted []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, auditFilePrefix) || !strings.HasSuffix(name, auditFileExt) {
			continue
		}
		dateStr := strings.TrimSuffix(strings.TrimPrefix(name, auditFilePrefix), auditFileExt)
		// HA instances append ".<instance>" before the extension; the file
		// date is everything before the first dot.
		if i := strings.Index(dateStr, "."); i >= 0 {
			dateStr = dateStr[:i]
		}
		day, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			// Not a dated audit file (e.g. a stray note); leave it alone.
			continue
		}
		if !day.Before(cutoff) {
			continue
		}
		path := filepath.Join(dir, name)
		if err := os.Remove(path); err != nil {
			log.Warn("audit retention: delete failed", slog.String("path", path), slog.String("detail", err.Error()))
			continue
		}
		log.Info("audit retention: pruned old audit file",
			slog.String("path", path),
			slog.String("file_date", dateStr),
			slog.Int("retention_days", retentionDays),
		)
		deleted = append(deleted, path)
	}
	return deleted, nil
}

// runAuditRetention prunes once at startup and then every interval until
// ctx is cancelled. nowFn is injectable for tests; nil selects time.Now.
func runAuditRetention(ctx context.Context, dir string, retentionDays int, interval time.Duration, nowFn func() time.Time, log *slog.Logger) {
	if retentionDays <= 0 {
		return
	}
	if interval <= 0 {
		interval = time.Hour
	}
	if nowFn == nil {
		nowFn = time.Now
	}
	prune := func() {
		if _, err := PruneAuditFiles(dir, retentionDays, nowFn(), log); err != nil {
			log.Warn("audit retention sweep failed", slog.String("detail", err.Error()))
		}
	}
	prune()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			prune()
		}
	}
}

func midnightUTC(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}
