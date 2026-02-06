// Package context implements context-aware password checking.
//
// It detects when passwords contain user-specific information such as
// usernames, email addresses, company names, or other personal context
// that makes passwords easier to guess.
//
// Context words are normalized (lowercased, trimmed) and checked against
// the password using exact matching, substring detection, and leetspeak
// variant detection.
package context

import (
	"fmt"
	"strings"

	"github.com/rafaelsanzio/passcheck/internal/issue"
	"github.com/rafaelsanzio/passcheck/internal/leet"
)

// Options holds configuration for context-aware checking.
type Options struct {
	// ContextWords is a list of user-specific terms to detect in passwords.
	// Examples: username, email, company name, personal information.
	// Words shorter than 3 characters are ignored to avoid false positives.
	ContextWords []string
}

// DefaultOptions returns the recommended default options.
// By default, no context words are checked.
func DefaultOptions() Options {
	return Options{
		ContextWords: nil,
	}
}

// Check runs context-aware checks with default options and returns
// a slice of structured issues for any context words found.
//
// This is a convenience wrapper around [CheckWith] using [DefaultOptions].
func Check(password string) []issue.Issue {
	return CheckWith(password, DefaultOptions())
}

// CheckWith runs context-aware checks with custom options and returns
// a slice of structured issues for any context words found.
//
// The function checks for:
//  1. Exact matches (case-insensitive)
//  2. Substring matches (case-insensitive)
//  3. Leetspeak variants of context words
//  4. Email component extraction and matching
//
// Words shorter than 3 characters are skipped to reduce false positives.
func CheckWith(password string, opts Options) []issue.Issue {
	if len(opts.ContextWords) == 0 {
		return nil
	}

	// Normalize password for comparison
	pwLower := strings.ToLower(password)
	pwNormalized := leet.Normalize(pwLower)

	var issues []issue.Issue
	seen := make(map[string]bool) // Deduplicate issues

	for _, word := range opts.ContextWords {
		// Normalize and validate context word
		normalized := normalizeContextWord(word)
		if len(normalized) < 3 {
			continue // Skip short words to avoid false positives
		}

		// Extract email parts if the word looks like an email
		words := extractWords(normalized)

		// Check each extracted word
		for _, w := range words {
			if len(w) < 3 {
				continue
			}

			// Skip if we've already reported this word
			if seen[w] {
				continue
			}

			// Check for matches
			if containsContextWord(pwLower, pwNormalized, w) {
				issues = append(issues, issue.New(
					issue.CodeContextWord,
					formatContextMessage(w),
					issue.CategoryContext,
					issue.SeverityHigh,
				))
				seen[w] = true
			}
		}
	}

	return issues
}

// normalizeContextWord normalizes a context word for comparison.
// It lowercases and trims whitespace.
func normalizeContextWord(word string) string {
	return strings.TrimSpace(strings.ToLower(word))
}

// extractWords extracts individual words from a context term.
// For emails, it extracts the local part, domain parts, and TLD.
// For other strings, it splits on common separators.
func extractWords(word string) []string {
	// Check if it's an email
	if strings.Contains(word, "@") {
		return extractEmailParts(word)
	}

	// Start with the original word
	result := []string{word}

	// Split on common separators
	separators := []string{".", "-", "_", " "}
	parts := []string{word}

	for _, sep := range separators {
		var newParts []string
		for _, part := range parts {
			split := strings.Split(part, sep)
			newParts = append(newParts, split...)
		}
		parts = newParts
	}

	// Add split parts to result
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" && part != word {
			result = append(result, part)
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, part := range result {
		if !seen[part] {
			unique = append(unique, part)
			seen[part] = true
		}
	}

	return unique
}

// extractEmailParts extracts meaningful parts from an email address.
// For "john.doe@acme.com", it returns ["john", "doe", "acme", "com", "john.doe"].
func extractEmailParts(email string) []string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return []string{email}
	}

	local := parts[0]
	domain := parts[1]

	var result []string

	// Add the full local part
	result = append(result, local)

	// Split local part on dots, hyphens, underscores
	localParts := strings.FieldsFunc(local, func(r rune) bool {
		return r == '.' || r == '-' || r == '_'
	})
	result = append(result, localParts...)

	// Split domain on dots
	domainParts := strings.Split(domain, ".")
	for _, part := range domainParts {
		result = append(result, part)

		// Also split domain parts on hyphens and underscores
		// e.g., "acme-corp" -> ["acme", "corp"]
		if strings.ContainsAny(part, "-_") {
			subParts := strings.FieldsFunc(part, func(r rune) bool {
				return r == '-' || r == '_'
			})
			result = append(result, subParts...)
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, part := range result {
		part = strings.TrimSpace(part)
		if part != "" && !seen[part] {
			unique = append(unique, part)
			seen[part] = true
		}
	}

	return unique
}

// containsContextWord checks if the password contains the context word.
// It checks both the original lowercased password and the leetspeak-normalized version.
func containsContextWord(pwLower, pwNormalized, word string) bool {
	// Check exact substring match
	if strings.Contains(pwLower, word) {
		return true
	}

	// Check leetspeak-normalized version
	wordNormalized := leet.Normalize(word)
	return strings.Contains(pwNormalized, wordNormalized)
}

// formatContextMessage creates a human-readable message for a context word match.
func formatContextMessage(word string) string {
	return fmt.Sprintf("Contains personal information: \"%q\"", word)
}
