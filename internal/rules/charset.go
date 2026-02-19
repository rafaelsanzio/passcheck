package rules

import (
	"github.com/rafaelsanzio/passcheck/internal/entropy"
	"github.com/rafaelsanzio/passcheck/internal/issue"
)

// checkCharsets verifies the password contains characters from the
// character sets enabled in opts (uppercase, lowercase, digits, symbols).
//
// It performs a single pass over the password for efficiency, then reports
// all missing character sets at once.
func checkCharsets(password string, opts Options) []issue.Issue {
	if password == "" {
		return nil
	}

	cs, _ := entropy.AnalyzeCharsets(password)

	var issues []issue.Issue
	if opts.RequireUpper && !cs.HasUpper {
		issues = append(issues, issue.New(issue.CodeRuleNoUpper, "Add at least one uppercase letter", issue.CategoryRule, issue.SeverityLow))
	}
	if opts.RequireLower && !cs.HasLower {
		issues = append(issues, issue.New(issue.CodeRuleNoLower, "Add at least one lowercase letter", issue.CategoryRule, issue.SeverityLow))
	}
	if opts.RequireDigit && !cs.HasDigit {
		issues = append(issues, issue.New(issue.CodeRuleNoDigit, "Add at least one digit", issue.CategoryRule, issue.SeverityLow))
	}
	if opts.RequireSymbol && !cs.HasSymbol {
		issues = append(issues, issue.New(issue.CodeRuleNoSymbol, "Add at least one symbol (!@#$%^&*...)", issue.CategoryRule, issue.SeverityLow))
	}
	return issues
}

