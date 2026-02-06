// Package dictionary implements password dictionary checks.
//
// It checks passwords against a curated set of common passwords, common
// English words, and their leetspeak variants to detect easily guessable
// passwords.
//
// Lookups are O(1) for exact password matches (hash map) and O(W×N)
// for word containment (W = wordlist size, N = password length), both
// well under 1 ms for typical inputs.
package dictionary

import (
	"fmt"
	"strings"
)

// Check runs all dictionary checks with the default (built-in) lists.
//
// This is a convenience wrapper around [CheckWith] using [DefaultOptions].
func Check(password string) []string {
	return CheckWith(password, DefaultOptions())
}

// CheckWith runs all dictionary checks against the password using the
// provided options, which may include user-supplied custom lists.
//
// The password is lowercased once and a leet-normalized variant is
// computed. Both forms are checked by each detector.
//
// Detection order:
//  1. Exact match against common passwords (plain + leet-normalized)
//  2. Common English word containment (plain + leet-normalized)
func CheckWith(password string, opts Options) []string {
	lower := strings.ToLower(password)

	// Compute leet-normalized variant unless disabled.
	normalized := lower
	if !opts.DisableLeet {
		normalized = normalizeLeet(lower)
	}

	var issues []string
	issues = append(issues, checkExactPasswordWith(lower, normalized, opts)...)
	issues = append(issues, checkCommonWordsWith(lower, normalized, opts)...)
	return issues
}

// checkExactPasswordWith reports whether the password (or its leet-normalized
// form) exactly matches a known common password — either the built-in set
// or a user-supplied custom list.
func checkExactPasswordWith(password, normalized string, opts Options) []string {
	var issues []string

	if isCommonPasswordIn(password, opts.CustomPasswords) {
		issues = append(issues, "This password appears in common password lists")
		return issues // exact match is the strongest signal; no need to also flag leet
	}

	if normalized != password && isCommonPasswordIn(normalized, opts.CustomPasswords) {
		issues = append(issues, "This is a leetspeak variant of a common password")
	}

	return issues
}

// checkCommonWordsWith reports common English words found inside the password
// (or its leet-normalized form), using both the built-in and custom word lists.
func checkCommonWordsWith(password, normalized string, opts Options) []string {
	seen := make(map[string]bool)
	var issues []string

	// Select word-finding function based on whether custom words are present.
	findWords := findCommonWords
	if len(opts.CustomWords) > 0 {
		findWords = func(pw string) []string {
			return findCommonWordsWithCustom(pw, opts.CustomWords)
		}
	}

	// Plain-text word matches.
	for _, word := range findWords(password) {
		seen[word] = true
		issues = append(issues, fmt.Sprintf(
			"Contains common word: '%s'", word,
		))
	}

	// Leet-normalized word matches (only report new words).
	if normalized != password {
		for _, word := range findWords(normalized) {
			if !seen[word] {
				seen[word] = true
				issues = append(issues, fmt.Sprintf(
					"Contains common word (via substitution): '%s'", word,
				))
			}
		}
	}

	return issues
}
