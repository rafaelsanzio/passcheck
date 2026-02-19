// Package passphrase implements passphrase detection and word counting.
//
// It detects word boundaries in passwords (spaces, hyphens, camelCase, snake_case)
// and counts distinct words to identify passphrases. This enables passphrase-friendly
// scoring that rewards multi-word combinations over complex short passwords.
package passphrase

import (
	"strings"
	"unicode"
)

// Info holds passphrase detection results.
type Info struct {
	IsPassphrase bool   // true if detected as a passphrase (meets word count threshold)
	WordCount    int    // number of distinct words found
	Words        []string // individual words (lowercased, deduplicated)
}

// Detect analyzes a password and returns passphrase information.
// It detects word boundaries using spaces, hyphens, camelCase, and snake_case.
//
// minWords is the minimum number of words required to consider it a passphrase.
func Detect(password string, minWords int) Info {
	if minWords < 1 {
		minWords = 1
	}

	words := extractWords(password)
	uniqueWords := deduplicate(words)

	info := Info{
		WordCount: len(uniqueWords),
		Words:     uniqueWords,
	}
	info.IsPassphrase = info.WordCount >= minWords

	return info
}

// extractWords splits the password into words using multiple strategies:
// 1. Spaces and hyphens as explicit separators
// 2. camelCase boundaries (lowercase followed by uppercase)
// 3. snake_case boundaries (underscores)
// 4. Consecutive digits or symbols as separators
func extractWords(password string) []string {
	if len(password) == 0 {
		return nil
	}

	var words []string
	var current strings.Builder
	runes := []rune(password)

	for i, r := range runes {
		// Explicit separators: space, hyphen, underscore
		if r == ' ' || r == '-' || r == '_' {
			if current.Len() > 0 {
				words = append(words, current.String())
				current.Reset()
			}
			continue
		}

		// camelCase boundary: lowercase/underscore/digit followed by uppercase
		if i > 0 && unicode.IsUpper(r) {
			prev := runes[i-1]
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || prev == '_' {
				if current.Len() > 0 {
					words = append(words, current.String())
					current.Reset()
				}
			}
		}

		// Transition from letter to digit/symbol or vice versa can be a boundary
		// (but only if we have accumulated a word)
		if i > 0 && current.Len() > 0 {
			prev := runes[i-1]
			prevIsLetter := unicode.IsLetter(prev)
			currIsLetter := unicode.IsLetter(r)
			prevIsDigit := unicode.IsDigit(prev)
			currIsDigit := unicode.IsDigit(r)

			// Letter-to-digit or digit-to-letter transition
			if (prevIsLetter && currIsDigit) || (prevIsDigit && currIsLetter) {
				// Only split if we have a reasonable word (at least 2 chars)
				if current.Len() >= 2 {
					words = append(words, current.String())
					current.Reset()
				}
			}
		}

		// Accumulate character (skip control chars)
		if !unicode.IsControl(r) {
			current.WriteRune(unicode.ToLower(r))
		}
	}

	// Add final word
	if current.Len() > 0 {
		words = append(words, current.String())
	}

	return words
}

// deduplicate removes duplicate words (case-insensitive) and filters out
// very short "words" (less than 2 characters) which are likely not real words.
func deduplicate(words []string) []string {
	if len(words) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	var unique []string

	for _, w := range words {
		// Filter out very short "words" (likely noise)
		if len(w) < 2 {
			continue
		}
		if !seen[w] {
			seen[w] = true
			unique = append(unique, w)
		}
	}

	return unique
}
