package feedback

import (
	"fmt"

	"github.com/rafaelsanzio/passcheck/internal/entropy"
	"github.com/rafaelsanzio/passcheck/internal/scoring"
)

// Thresholds for positive feedback.
const (
	goodLengthThreshold  = 16 // characters
	highEntropyThreshold = 60 // bits
)

// GeneratePositive inspects the password and the issue set to produce
// encouraging messages about the password's strengths.
//
// Only aspects that are genuinely strong are praised — a short password
// does not get "Good length", and a password full of patterns does not
// get "No common patterns detected".
func GeneratePositive(password string, issues scoring.IssueSet, entropyBits float64) []string {
	var msgs []string

	runeLen := len([]rune(password))

	// Length praise.
	if runeLen >= goodLengthThreshold {
		msgs = append(msgs, fmt.Sprintf("Good length (%d characters)", runeLen))
	}

	// Character-set diversity praise.
	info := entropy.AnalyzeCharsets(password)
	if count := info.SetCount(); count >= 3 {
		msgs = append(msgs, fmt.Sprintf(
			"Good character diversity (%d of 4 character types)", count,
		))
	}

	// No pattern issues → praise.
	if len(issues.Patterns) == 0 && runeLen > 0 {
		msgs = append(msgs, "No common patterns detected")
	}

	// No dictionary issues → praise.
	if len(issues.Dictionary) == 0 && runeLen > 0 {
		msgs = append(msgs, "Not found in common password lists")
	}

	// High entropy → praise.
	if entropyBits >= highEntropyThreshold {
		msgs = append(msgs, fmt.Sprintf("Good entropy (%.0f bits)", entropyBits))
	}

	return msgs
}
