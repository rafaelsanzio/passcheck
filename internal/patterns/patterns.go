// Package patterns implements password pattern detection.
//
// It detects common weak patterns such as keyboard walks (qwerty, asdf),
// sequential runs (abcd, 1234), repeated blocks (abcabc), and simple
// leetspeak substitutions (p@ssw0rd, adm1n).
//
// Each detector is a standalone checker function. The main Check function
// orchestrates all detectors in order, operating on a lowercased copy of
// the password for case-insensitive matching.
package patterns

import "strings"

// checker is a function that examines a (lowercased) password and returns
// a slice of issue descriptions for any patterns found.
type checker func(password string) []string

// Check runs all pattern detection checks with default options and returns
// a slice of issue messages for any patterns found.
//
// This is a convenience wrapper around [CheckWith] using [DefaultOptions].
func Check(password string) []string {
	return CheckWith(password, DefaultOptions())
}

// CheckWith runs all pattern detection checks with custom options and returns
// a slice of issue messages for any patterns found.
//
// The password is lowercased once before being passed to individual
// detectors for case-insensitive matching.
//
// Detection order:
//  1. Keyboard patterns (QWERTY rows, vertical walks, numpad)
//  2. Sequential runs (alphabetic, numeric, forward and reverse)
//  3. Repeated blocks (abcabc, 121212)
//  4. Leetspeak substitutions (p@ssw0rd → password)
func CheckWith(password string, opts Options) []string {
	lower := strings.ToLower(password)

	checkers := []checker{
		func(pw string) []string { return checkKeyboard(pw, opts) },
		func(pw string) []string { return checkSequence(pw, opts) },
		checkRepeatedBlocks,
		checkSubstitution,
	}

	var issues []string
	for _, check := range checkers {
		issues = append(issues, check(lower)...)
	}
	return issues
}
