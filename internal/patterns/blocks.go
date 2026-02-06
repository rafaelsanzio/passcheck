package patterns

import (
	"fmt"

	"github.com/rafaelsanzio/passcheck/internal/issue"
)

// DefaultBlockMinLen is the minimum length of a repeating unit (block)
// that triggers detection. Set to 2 so that patterns like "1212" and
// "abab" are caught, while single-character repeats ("aaa") are left
// to the rules package.
const DefaultBlockMinLen = 2

// maxBlockLen caps the maximum block length to check. No legitimate
// password contains a repeated block longer than this, and the cap
// keeps the algorithm O(n) instead of O(n²) for long inputs.
const maxBlockLen = 64

// maxBlockIssues limits the number of distinct repeated-block issues
// reported. Reporting more than this adds noise without actionable value.
const maxBlockIssues = 5

// checkRepeatedBlocks detects substrings that appear consecutively more
// than once, e.g. "abcabc" (block "abc"), "1212" (block "12").
//
// Blocks whose characters are all identical (e.g. "aa" in "aaaa") are
// skipped because single-character repetition is handled by the rules
// package.
func checkRepeatedBlocks(password string) []issue.Issue {
	runes := []rune(password)
	n := len(runes)

	if n < DefaultBlockMinLen*2 {
		return nil
	}

	// Upper-bound the block length to keep the scan bounded.
	limit := n / 2
	if limit > maxBlockLen {
		limit = maxBlockLen
	}

	seen := make(map[string]bool)
	var issues []issue.Issue

	for blockLen := DefaultBlockMinLen; blockLen <= limit; blockLen++ {
		for start := 0; start+blockLen*2 <= n; start++ {
			block := string(runes[start : start+blockLen])

			// Skip single-character blocks (handled by rules.checkRepeatedChars).
			if allSameRune(runes[start : start+blockLen]) {
				continue
			}

			next := string(runes[start+blockLen : start+blockLen*2])
			if block == next && !seen[block] {
				seen[block] = true
				issues = append(issues, issue.New(
					issue.CodePatternBlock,
					fmt.Sprintf("Contains repeated block: '%s'", block),
					issue.CategoryPattern,
					issue.SeverityMed,
				))
				if len(issues) >= maxBlockIssues {
					return issues
				}
			}
		}
	}

	return issues
}

// allSameRune reports whether every rune in the slice is identical.
func allSameRune(runes []rune) bool {
	if len(runes) == 0 {
		return true
	}
	first := runes[0]
	for _, r := range runes[1:] {
		if r != first {
			return false
		}
	}
	return true
}
