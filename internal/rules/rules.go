// Package rules implements basic password policy checks.
//
// It validates passwords against fundamental rules such as minimum length,
// character set requirements, whitespace detection, and repeated characters.
//
// Each rule is implemented as a standalone checker function that receives
// a password and returns a slice of issue messages. The main Check function
// orchestrates all checkers in order.
package rules

import "github.com/rafaelsanzio/passcheck/internal/issue"

// checker is a function that examines a password and returns
// a slice of structured issues for any violations found.
type checker func(password string) []issue.Issue

// Check runs all basic rule checks with default options and returns
// a slice of structured issues for any rules that were violated.
//
// This is a convenience wrapper around [CheckWith] using [DefaultOptions].
func Check(password string) []issue.Issue {
	return CheckWith(password, DefaultOptions())
}

// CheckWith runs all basic rule checks with custom options and returns
// a slice of structured issues for any rules that were violated.
//
// Rules are evaluated in a fixed order:
//  1. Minimum length
//  2. Character set requirements (uppercase, lowercase, digits, symbols)
//  3. Whitespace and control characters
//  4. Repeated consecutive characters
func CheckWith(password string, opts Options) []issue.Issue {
	checkers := []checker{
		func(pw string) []issue.Issue { return checkMinLength(pw, opts) },
		func(pw string) []issue.Issue { return checkCharsets(pw, opts) },
		checkWhitespace,
		func(pw string) []issue.Issue { return checkRepeatedChars(pw, opts) },
	}

	var issues []issue.Issue
	for _, check := range checkers {
		issues = append(issues, check(password)...)
	}
	return issues
}
