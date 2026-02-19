package hibpcheck

import (
	"github.com/rafaelsanzio/passcheck/internal/issue"
)

// Options holds configuration for the HIBP check.
type Options struct {
	// Checker is an optional interface to check passwords against HIBP.
	Checker interface {
		Check(password string) (breached bool, count int, err error)
	}
	// MinOccurrences is the minimum breach count required to report an issue.
	MinOccurrences int
	// Result is an optional pre-computed HIBP check result.
	Result *Result
}

// Result is a pre-computed HIBP check result.
type Result struct {
	Breached bool
	Count    int
}

// CheckWith evaluates the password against a breach database (HIBP).
func CheckWith(password string, opts Options) []issue.Issue {
	var breached bool
	var count int

	if opts.Result != nil {
		breached = opts.Result.Breached
		count = opts.Result.Count
	} else if opts.Checker != nil {
		var err error
		breached, count, err = opts.Checker.Check(password)
		if err != nil {
			// Graceful degradation: errors from the HIBP checker are intentionally
			// ignored so that the core analysis can continue even if the network
			// or the API is down.
			breached, count = false, 0
		}
	}


	minOcc := opts.MinOccurrences
	if minOcc < 1 {
		minOcc = 1
	}

	if breached && count >= minOcc {
		return []issue.Issue{
			issue.New(
				issue.CodeHIBPBreached,
				"Password has been found in a data breach.",
				issue.CategoryBreach,
				issue.SeverityHigh,
			),
		}
	}

	return nil
}
