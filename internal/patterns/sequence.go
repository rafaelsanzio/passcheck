package patterns

import "fmt"

// DefaultSequenceMinLen is the minimum number of characters in an arithmetic
// progression that trigger a detection.
const DefaultSequenceMinLen = 4

// sequenceSteps lists the step values checked for arithmetic progressions.
//
//   - +1 / -1 : consecutive characters (abcd, dcba, 1234, 4321)
//   - +2 / -2 : alternating characters  (2468, 8642, aceg, geca)
var sequenceSteps = []int{1, -1, 2, -2}

// checkSequence detects arithmetic character sequences in the password.
//
// A sequence is a run where each character's Unicode code point differs
// from its predecessor by a constant step. Both ascending and descending
// progressions with steps of 1 and 2 are detected.
func checkSequence(password string, opts Options) []string {
	runes := []rune(password)
	if len(runes) < opts.SequenceMinLen {
		return nil
	}

	seen := make(map[string]bool)
	var issues []string

	for _, step := range sequenceSteps {
		for _, run := range findArithmeticRuns(runes, step, opts.SequenceMinLen) {
			if !seen[run] {
				seen[run] = true
				issues = append(issues, fmt.Sprintf(
					"Contains sequence: '%s'", run,
				))
			}
		}
	}

	return issues
}

// findArithmeticRuns scans runes for maximal contiguous runs where each
// pair of adjacent runes differs by exactly step. Only runs of at least
// minLen are returned.
func findArithmeticRuns(runes []rune, step, minLen int) []string {
	var results []string

	runStart := 0
	for i := 1; i < len(runes); i++ {
		if int(runes[i])-int(runes[i-1]) != step {
			if i-runStart >= minLen {
				results = append(results, string(runes[runStart:i]))
			}
			runStart = i
		}
	}

	// Flush the final run.
	if len(runes)-runStart >= minLen {
		results = append(results, string(runes[runStart:]))
	}

	return results
}
