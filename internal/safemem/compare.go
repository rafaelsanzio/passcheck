// Package safemem provides utilities for handling sensitive data in memory.
//
// This file provides constant-time comparison primitives to reduce
// timing side channels when comparing secrets (e.g. password blocklists).

package safemem

import "crypto/subtle"

// ConstantTimeCompare compares two strings in constant time.
// It returns true only when a and b have the same length and identical bytes.
// Execution time does not depend on length, content, or where they differ.
//
// Use this when comparing user input against secrets (e.g. blocklist entries)
// to avoid leaking information through timing.
func ConstantTimeCompare(a, b string) bool {
	return constantTimeCompareByte(a, b) == 1
}

// ConstantTimeEqual returns 1 if a and b are equal (constant time), 0 otherwise.
// Use when combining results without branching (e.g. found |= ConstantTimeEqual(a, b)).
func ConstantTimeEqual(a, b string) int {
	return constantTimeCompareByte(a, b)
}

// constantTimeCompareByte returns 1 if a and b are equal (same length and bytes), 0 otherwise.
// Work is proportional to max(len(a), len(b)) so timing does not leak length.
func constantTimeCompareByte(a, b string) int {
	na, nb := len(a), len(b)
	n := na
	if nb > n {
		n = nb
	}
	var diff int
	for i := 0; i < n; i++ {
		var ai, bi byte
		if i < na {
			ai = a[i]
		}
		if i < nb {
			bi = b[i]
		}
		diff |= int(ai) ^ int(bi)
	}
	diff |= na ^ nb
	return constantTimeIntEqZero(diff)
}

// constantTimeIntEqZero returns 1 if x == 0, 0 otherwise, in constant time.
func constantTimeIntEqZero(x int) int {
	eq := 1
	for i := 0; i < 8; i++ {
		eq &= subtle.ConstantTimeByteEq(byte(x>>(i*8)), 0)
	}
	return eq
}

// ConstantTimeContains reports whether needle is a substring of haystack,
// using constant-time comparisons so that execution time does not depend
// on the position of the match (or absence of match).
//
// If needle is empty, returns true. If needle is longer than haystack,
// returns false. Otherwise scans every possible starting position and
// combines results in constant time.
func ConstantTimeContains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	var found int
	for i := 0; i <= len(haystack)-len(needle); i++ {
		found |= constantTimeCompareByte(haystack[i:i+len(needle)], needle)
	}
	return found == 1
}
