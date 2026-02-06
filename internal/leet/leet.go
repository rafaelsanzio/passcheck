// Package leet provides leetspeak normalization utilities shared by
// the pattern-detection and dictionary-lookup packages.
package leet

import "strings"

// Map maps common leetspeak characters to their primary alphabetic
// equivalent. Only the single most likely substitution is stored to
// keep normalization deterministic and O(n).
var Map = map[rune]rune{
	'@': 'a',
	'4': 'a',
	'8': 'b',
	'3': 'e',
	'1': 'i',
	'!': 'i',
	'|': 'l',
	'0': 'o',
	'$': 's',
	'5': 's',
	'7': 't',
	'+': 't',
}

// Normalize replaces leetspeak characters in s with their primary
// alphabetic equivalents. If no substitutions apply the original string
// is returned, avoiding allocation.
func Normalize(s string) string {
	if !Contains(s) {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))

	for _, r := range s {
		if repl, ok := Map[r]; ok {
			b.WriteRune(repl)
		} else {
			b.WriteRune(r)
		}
	}

	return b.String()
}

// Contains reports whether s contains any leetspeak characters.
func Contains(s string) bool {
	for _, r := range s {
		if _, ok := Map[r]; ok {
			return true
		}
	}
	return false
}
