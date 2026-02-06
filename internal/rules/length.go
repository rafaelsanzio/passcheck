package rules

import (
	"fmt"

	"github.com/rafaelsanzio/passcheck/internal/issue"
)

// DefaultMinLength is the minimum number of characters required in a password.
const DefaultMinLength = 12

// checkMinLength verifies the password meets the minimum length requirement.
// It counts Unicode code points (runes), not bytes.
func checkMinLength(password string, opts Options) []issue.Issue {
	length := len([]rune(password))
	if length < opts.MinLength {
		return []issue.Issue{
			issue.New(
				issue.CodeRuleTooShort,
				fmt.Sprintf("Password is too short (%d chars, minimum %d)", length, opts.MinLength),
				issue.CategoryRule,
				issue.SeverityLow,
			),
		}
	}
	return nil
}
