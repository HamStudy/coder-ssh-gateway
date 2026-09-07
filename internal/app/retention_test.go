package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeAuditFixture(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
	return path
}

func TestPruneAuditFiles(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 9, 4, 15, 30, 0, 0, time.UTC)

	old := writeAuditFixture(t, dir, "audit-2026-05-01.jsonl")     // 125 days old
	edge := writeAuditFixture(t, dir, "audit-2026-06-06.jsonl")    // exactly 90 days old
	recent := writeAuditFixture(t, dir, "audit-2026-09-03.jsonl")  // yesterday
	stray := writeAuditFixture(t, dir, "audit-notes.txt")          // wrong ext
	badDate := writeAuditFixture(t, dir, "audit-not-a-date.jsonl") // unparseable

	deleted, err := PruneAuditFiles(dir, 90, now, nil)
	if err != nil {
		t.Fatalf("PruneAuditFiles: %v", err)
	}
	if len(deleted) != 1 || deleted[0] != old {
		t.Fatalf("deleted = %v, want [%s]", deleted, old)
	}
	for _, kept := range []string{edge, recent, stray, badDate} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("kept file %s missing: %v", filepath.Base(kept), err)
		}
	}
}

func TestPruneAuditFilesDisabledAndCancel(t *testing.T) {
	dir := t.TempDir()
	old := writeAuditFixture(t, dir, "audit-2020-01-01.jsonl")

	// retentionDays <= 0 disables the job entirely (returns immediately).
	runAuditRetention(context.Background(), dir, 0, time.Millisecond, nil, nil)
	if _, err := os.Stat(old); err != nil {
		t.Errorf("disabled retention deleted %s: %v", old, err)
	}

	// A cancelled context stops the loop after the startup sweep; the sweep
	// with the injected clock still prunes.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runAuditRetention(ctx, dir, 90, time.Hour,
		func() time.Time { return time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC) }, nil)
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("startup sweep did not prune old file, stat err = %v", err)
	}
}

// HA instance-suffixed audit files (audit-<date>.<instance>.jsonl) prune on
// the same schedule as plain ones.
func TestPruneAuditFilesInstanceSuffix(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().AddDate(0, 0, -30).Format("2006-01-02")
	fresh := time.Now().Format("2006-01-02")
	for _, name := range []string{"audit-" + old + ".gw-pod-1.jsonl", "audit-" + old + ".jsonl", "audit-" + fresh + ".gw-pod-1.jsonl"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	deleted, err := PruneAuditFiles(dir, 7, time.Now(), nil)
	if err != nil {
		t.Fatalf("PruneAuditFiles: %v", err)
	}
	if len(deleted) != 2 {
		t.Fatalf("deleted = %v, want both stale files", deleted)
	}
	for _, name := range []string{"audit-" + fresh + ".gw-pod-1.jsonl"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("fresh file pruned: %v", err)
		}
	}
}
