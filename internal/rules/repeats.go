package rules

import "fmt"

// DefaultMaxRepeats is the maximum number of consecutive identical characters
// allowed before an issue is reported. A value of 3 means "aaa" is flagged.
const DefaultMaxRepeats = 3

// checkRepeatedChars detects runs of consecutive identical characters that
// meet or exceed the repeat threshold from opts.
//
// For example, with the default threshold of 3:
//   - "aaa"  → flagged (3 consecutive 'a')
//   - "aa"   → allowed (only 2)
//   - "aaab" → flagged (3 consecutive 'a')
func checkRepeatedChars(password string, opts Options) []string {
	runes := []rune(password)
	if len(runes) < opts.MaxRepeats {
		return nil
	}

	seen := make(map[rune]bool)
	var issues []string

	count := 1
	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1] {
			count++
		} else {
			count = 1
		}

		if count >= opts.MaxRepeats && !seen[runes[i]] {
			seen[runes[i]] = true
			repeated := string(repeatRune(runes[i], count))
			issues = append(issues, fmt.Sprintf(
				"Avoid repeating character '%s'", repeated,
			))
		}
	}

	return issues
}

// repeatRune creates a slice of n copies of a rune.
func repeatRune(r rune, n int) []rune {
	result := make([]rune, n)
	for i := range result {
		result[i] = r
	}
	return result
}
