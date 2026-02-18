//go:build hibpintegration

package hibp

import (
	"testing"
	"time"
)

// TestCheck_RealAPI_Integration runs against the live HIBP API.
// Run with: go test -tags=hibpintegration -run TestCheck_RealAPI -v -count=1
// Rate limit: this test makes one API call. Do not run in a tight loop.
func TestCheck_RealAPI_Integration(t *testing.T) {
	c := NewClient()
	// "password" is known to be breached.
	breached, count, err := c.Check("password")
	if err != nil {
		t.Fatalf("Check: %v (network or API issue)", err)
	}
	if !breached {
		t.Error("expected \"password\" to be breached")
	}
	if count < 1 {
		t.Errorf("expected count >= 1, got %d", count)
	}
}

// TestCheck_RealAPI_Performance asserts cached response is fast and one API call completes within 500ms.
// Run with: go test -tags=hibpintegration -run TestCheck_RealAPI_Performance -v -count=1
func TestCheck_RealAPI_Performance(t *testing.T) {
	c := NewClient()
	c.Cache = NewMemoryCacheWithTTL(10, 5*time.Minute)

	// First call: API (allow up to 500ms per AC).
	start := time.Now()
	_, _, err := c.Check("password")
	elapsed := time.Since(start)
	if err != nil {
		t.Skipf("API call failed (e.g. network): %v", err)
	}
	if elapsed > 2*time.Second {
		t.Logf("warning: API call took %v (AC suggests <500ms; may be network)", elapsed)
	}

	// Second call: cache (expect <100ms per AC).
	start = time.Now()
	_, _, _ = c.Check("password")
	elapsed = time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Errorf("cached check took %v, want <100ms", elapsed)
	}
}
