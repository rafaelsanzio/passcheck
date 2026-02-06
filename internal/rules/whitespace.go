package rules

import (
	"unicode"

	"github.com/rafaelsanzio/passcheck/internal/issue"
)

// checkWhitespace detects whitespace characters (spaces, tabs, newlines)
// and control characters in the password.
//
// Whitespace and control characters are discouraged because they can cause
// issues with copy-paste, display, and compatibility across systems.
func checkWhitespace(password string) []issue.Issue {
	var hasWhitespace, hasControl bool

	for _, r := range password {
		switch {
		case unicode.IsSpace(r):
			hasWhitespace = true
		case unicode.IsControl(r):
			hasControl = true
		}
		// Early exit once both are detected.
		if hasWhitespace && hasControl {
			break
		}
	}

	var issues []issue.Issue
	if hasWhitespace {
		issues = append(issues, issue.New(issue.CodeRuleWhitespace, "Remove whitespace characters (spaces, tabs, newlines)", issue.CategoryRule, issue.SeverityLow))
	}
	if hasControl {
		issues = append(issues, issue.New(issue.CodeRuleControlChar, "Remove control characters", issue.CategoryRule, issue.SeverityLow))
	}
	return issues
}
