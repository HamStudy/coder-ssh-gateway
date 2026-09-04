// Package testleaks provides a helper to detect goroutine leaks in tests.
//
// Convention: every server/tunnel/store package test file should call
//   defer testleaks.Verify(t)
// or use TestMain with goleak.VerifyTestMain.
//
// This package wraps goleak.VerifyNone with standard ignore options
// that account for goroutine spawn timing in our tests.
package testleaks

import (
	"testing"

	"go.uber.org/goleak"
)

// Verify checks that the current test has no leaked goroutines.
// Call this via defer in each test that may spawn goroutines:
//
//	func TestMyServer(t *testing.T) {
//	    defer Verify(t)
//	    // ... test code that spawns goroutines
//	}
func Verify(t testing.TB) {
	goleak.VerifyNone(t)
}

// VerifyTestMain is for use in a TestMain function:
//
//	func TestMain(m *testing.M) {
//	    goleak.VerifyTestMain(m)
//	}
func VerifyTestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
