package version

import (
	"testing"
)

func TestString(t *testing.T) {
	// Ensure String() returns a non-empty string
	s := String()
	if s == "" {
		t.Fatal("String() returned empty string")
	}
	// Should contain the module name or version
	if s == "dev" {
		// This is fine for dev mode
		t.Logf("String() in dev mode: %s", s)
	}
}

func TestVersionVars(t *testing.T) {
	// Version, Commit, Date should be set (even if to "dev" defaults)
	if Version == "" {
		t.Error("Version is empty")
	}
	if Commit == "" {
		t.Error("Commit is empty")
	}
	if Date == "" {
		t.Error("Date is empty")
	}
}

func TestDevDefaults(t *testing.T) {
	// When not built with ldflags, should default to "dev"
	if Version != "dev" || Commit != "dev" || Date != "dev" {
		t.Logf("Non-dev mode: Version=%s, Commit=%s, Date=%s", Version, Commit, Date)
	}
}
