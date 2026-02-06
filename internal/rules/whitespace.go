package rules

import "unicode"

// checkWhitespace detects whitespace characters (spaces, tabs, newlines)
// and control characters in the password.
//
// Whitespace and control characters are discouraged because they can cause
// issues with copy-paste, display, and compatibility across systems.
func checkWhitespace(password string) []string {
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

	var issues []string
	if hasWhitespace {
		issues = append(issues, "Remove whitespace characters (spaces, tabs, newlines)")
	}
	if hasControl {
		issues = append(issues, "Remove control characters")
	}
	return issues
}
