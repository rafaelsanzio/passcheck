// Package safemem provides utilities for handling sensitive data in memory.
//
// Go strings are immutable and managed by the garbage collector, so they
// cannot be reliably zeroed. The functions in this package operate on
// mutable []byte slices, giving callers control over when sensitive data
// is cleared.
//
// Note: the Go runtime may still retain copies of the data in CPU caches,
// swap, or core dumps. This package reduces — but does not eliminate —
// the window of exposure.
package safemem

// Zero overwrites every byte in b with zero, clearing sensitive data.
//
// The caller is responsible for ensuring that no other live references
// to the underlying array remain (e.g. slices sharing the same backing).
//
//go:noinline
func Zero(b []byte) {
	clear(b)
}

// IsZeroed reports whether every byte in b is zero.
// Useful for verifying that Zero completed correctly in tests.
func IsZeroed(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
