package patterns

import (
	"fmt"

	"github.com/rafaelsanzio/passcheck/internal/issue"
)

// DefaultKeyboardMinLen is the minimum number of consecutive keyboard-adjacent
// characters that trigger a detection.
const DefaultKeyboardMinLen = 4

// keyboardLayouts holds all keyboard layout paths (forward and reversed),
// precomputed at package initialisation for efficiency.
var keyboardLayouts []string

// layoutIndex maps a starting byte to the list of (layout, offset) pairs
// where that byte appears, allowing O(1) lookup instead of scanning all
// layouts for every password position.
type layoutPos struct {
	layout string
	offset int
}

var layoutIndex map[byte][]layoutPos

func init() {
	rows := []string{
		// QWERTY horizontal rows
		"qwertyuiop",
		"asdfghjkl",
		"zxcvbnm",

		// Number row
		"1234567890",

		// QWERTY vertical columns (top → bottom)
		"qaz", "wsx", "edc", "rfv", "tgb", "yhn", "ujm",

		// QWERTY diagonals (top-left → bottom-right)
		"qwsz", "wedf", "erfc", "rtgv", "tyhb", "yujn", "uikm",

		// Numeric keypad rows
		"123", "456", "789",

		// Numeric keypad columns
		"147", "258", "369",

		// Numeric keypad diagonals
		"159", "357",
	}

	for _, row := range rows {
		keyboardLayouts = append(keyboardLayouts, row)
		if rev := reverseStr(row); rev != row {
			keyboardLayouts = append(keyboardLayouts, rev)
		}
	}

	// Build the reverse index for fast lookup.
	layoutIndex = make(map[byte][]layoutPos)
	for _, layout := range keyboardLayouts {
		for j := 0; j < len(layout); j++ {
			b := layout[j]
			layoutIndex[b] = append(layoutIndex[b], layoutPos{layout, j})
		}
	}
}

// checkKeyboard detects keyboard walk patterns in the password.
//
// For each starting position, it finds the longest consecutive run that
// appears in any known keyboard layout (forward or reversed). Runs of at
// least opts.KeyboardMinLen characters are reported. After a match the
// scanner skips past it so that overlapping sub-patterns (e.g. "werty"
// inside "qwerty") are not reported separately.
func checkKeyboard(password string, opts Options) []issue.Issue {
	if len(password) < opts.KeyboardMinLen {
		return nil
	}

	seen := make(map[string]bool)
	var issues []issue.Issue

	i := 0
	for i <= len(password)-opts.KeyboardMinLen {
		match := longestKeyboardRunAt(password, i)
		if len(match) >= opts.KeyboardMinLen {
			if !seen[match] {
				seen[match] = true
				issues = append(issues, issue.New(
					issue.CodePatternKeyboard,
					fmt.Sprintf("Contains keyboard pattern: '%s'", match),
					issue.CategoryPattern,
					issue.SeverityMed,
				))
			}
			i += len(match) // Skip past the matched region.
		} else {
			i++
		}
	}
	return issues
}

// longestKeyboardRunAt returns the longest consecutive keyboard-layout
// substring of password starting at the given byte offset.
//
// All keyboard layouts are ASCII-only, so byte-level indexing is safe
// even when the password contains multi-byte UTF-8 characters (UTF-8
// continuation bytes are always > 0x7F and will never match).
func longestKeyboardRunAt(password string, start int) string {
	var best string

	ch := password[start]
	positions, ok := layoutIndex[ch]
	if !ok {
		return ""
	}

	for _, pos := range positions {
		layout, j := pos.layout, pos.offset
		// Extend the match forward.
		k := 1
		for start+k < len(password) && j+k < len(layout) && password[start+k] == layout[j+k] {
			k++
		}
		if k > len(best) {
			best = password[start : start+k]
		}
	}

	return best
}

// reverseStr returns s with its characters in reverse order.
func reverseStr(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
