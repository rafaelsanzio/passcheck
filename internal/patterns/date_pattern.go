package patterns

import (
	"regexp"

	"github.com/rafaelsanzio/passcheck/internal/issue"
)

// dateRegex matches common date patterns (YYYY, MMDDYY, DDMMYY, MMDDYYYY).
// We simplify this by looking for specific numeric patterns that strongly resemble years or full dates.
// Matches 19xx, 20xx up to 2099, and common 6-8 digit date sequences starting with 01-31.
var dateRegex = regexp.MustCompile(`(?:19\d{2}|20\d{2}|(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])(?:\d{2}|\d{4}))`)

// CheckDates identifies substring sequences that look like dates (e.g., years, MMDDYY, DDMMYY).
func CheckDates(password string, minPatternLen int) []issue.Issue {
	matches := dateRegex.FindAllString(password, -1)
	if len(matches) == 0 {
		return nil
	}
	
	var issues []issue.Issue
	for _, m := range matches {
		if len(m) >= minPatternLen {
			issues = append(issues, issue.Issue{
				Category: issue.CategoryPattern,
				Severity: issue.SeverityMed,
				Code:     issue.CodePatternDate,
				Message:  "Contains a common date pattern ('" + m + "')",
				Pattern:  m,
			})
		}
	}
	return issues
}
