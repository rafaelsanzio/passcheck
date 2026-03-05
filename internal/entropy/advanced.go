// Package entropy implements password entropy calculation.
//
// This file provides pattern-aware entropy calculation. Instead of applying a
// post-hoc multiplicative reduction to the pool-size estimate, it uses a
// segment-based model: each detected pattern segment contributes only its
// intrinsic entropy — the bits needed to describe the pattern choice to an
// attacker who already knows the pattern class — while uncovered characters
// contribute the standard character-pool entropy.
package entropy

import (
	"math"
	"strings"

	"github.com/rafaelsanzio/passcheck/internal/issue"
)

// Keyboard walk and sequence search-space sizes, derived from the number of
// distinct choices an attacker must make to reproduce the pattern:
//
//   - keyboardWalkSpace: ~35 QWERTY/numpad starting positions × 4 walk
//     directions ≈ 140, rounded to 150 to include numpad diagonals.
//     All walks of length ≥ 4 fall within this space, so the constant is
//     independent of walk length.
//
//   - sequenceSpace: 36 possible starting characters (26 alpha + 10 digit)
//     × 2 directions (ascending / descending) × 2 step sizes (±1, ±2) = 144.
const (
	keyboardWalkSpace = 150.0
	sequenceSpace     = 144.0
)

// CalculateAdvanced calculates entropy using a segment-based model.
//
// The password is partitioned into two kinds of regions:
//
//  1. Pattern segments (identified by the Pattern field of each issue.Issue):
//     contribute only the intrinsic entropy of their pattern class
//     (see intrinsicPatternEntropy).
//
//  2. Free characters (not covered by any detected pattern): contribute the
//     standard character-pool entropy (bits = count × log2(poolSize)).
//
// Repeated-block patterns are counted once regardless of how many times the
// block repeats in the password; all repetitions are marked as covered but add
// no additional entropy.
//
// Issues whose Pattern field is empty are silently ignored (e.g. issues from
// rule or dictionary checkers that are unrelated to structural patterns).
func CalculateAdvanced(password string, patternIssues []issue.Issue) float64 {
	runes := []rune(password)
	n := len(runes)
	if n == 0 {
		return 0
	}

	info, _ := AnalyzeCharsets(password)
	pool := info.PoolSize()
	if pool == 0 {
		return 0
	}

	// covered[i] = true when rune i is accounted for by a detected pattern.
	covered := make([]bool, n)

	lowerRunes := []rune(strings.ToLower(password))
	patternEntropy := 0.0

	for _, iss := range patternIssues {
		pat := iss.Pattern
		if pat == "" {
			// No structured pattern attached; skip to avoid silently parsing
			// the human-readable Message (which would break on any text change).
			continue
		}

		patRunes := []rune(strings.ToLower(pat))
		patLen := len(patRunes)
		if patLen == 0 {
			continue
		}

		// Locate every occurrence of this pattern in the (lower-cased) password.
		// For keyboard/sequence issues, each independent occurrence contributes
		// its own intrinsic entropy (each is a new attacker guess).
		// For block issues, only the FIRST occurrence that covers previously
		// uncovered territory contributes entropy. This handles a subtlety: the
		// block detector reports every unique repeating sub-sequence, so a
		// password like "abcabcabc" generates overlapping block issues
		// ("abc", "bca", "cab"). Without the newlyCovered guard those issues
		// would together reconstruct the full simple entropy.
		firstSeen := true
		for start := 0; start+patLen <= n; {
			if !runesMatch(lowerRunes, start, patRunes) {
				start++
				continue
			}

			// Count how many of these positions are genuinely new before marking.
			newlyCovered := 0
			for i := start; i < start+patLen; i++ {
				if !covered[i] {
					newlyCovered++
				}
			}
			for i := start; i < start+patLen; i++ {
				covered[i] = true
			}

			switch iss.Code {
			case issue.CodePatternBlock:
				// Only the first occurrence that adds new coverage carries entropy.
				// Subsequent repetitions (and overlapping block variants) add zero.
				if firstSeen && newlyCovered > 0 {
					patternEntropy += intrinsicPatternEntropy(iss.Code, pat)
				}
			default:
				// Keyboard/sequence: each non-trivially placed occurrence is an
				// independent attacker guess.
				patternEntropy += intrinsicPatternEntropy(iss.Code, pat)
			}

			firstSeen = false
			start += patLen // skip to the next non-overlapping position
		}
	}

	// Count characters not covered by any pattern.
	freeCount := 0
	for _, c := range covered {
		if !c {
			freeCount++
		}
	}

	freeEntropy := float64(freeCount) * math.Log2(float64(pool))
	total := freeEntropy + patternEntropy
	if total < 0 {
		return 0
	}
	return total
}

// intrinsicPatternEntropy returns the entropy in bits that a single occurrence
// of the detected pattern contributes.
//
// Values are grounded in the attacker's search-space size for each class:
//
//   - Keyboard walk: an attacker enumerates (start key, direction) pairs.
//     With ~35 keys and ~4 directions the space is ≈ 150 → log2(150) ≈ 7.2 bits,
//     independent of walk length (longer walks do not increase the walk count).
//
//   - Sequence: attacker chooses (start character, direction, step).
//     36 starting chars × 2 directions × 2 step sizes = 144 → log2(144) ≈ 7.2 bits.
//
//   - Repeated block: the attacker knows the block repeats; they only need to
//     guess the block itself. Entropy = len(block) × log2(blockPool).
func intrinsicPatternEntropy(code, pattern string) float64 {
	switch code {
	case issue.CodePatternKeyboard:
		return math.Log2(keyboardWalkSpace)

	case issue.CodePatternSequence:
		return math.Log2(sequenceSpace)

	case issue.CodePatternBlock:
		// Only one copy of the block is secret; the repetitions are free.
		blockInfo, blockLen := AnalyzeCharsets(pattern)
		blockPool := blockInfo.PoolSize()
		if blockPool < 2 || blockLen == 0 {
			return 1.0
		}
		return float64(blockLen) * math.Log2(float64(blockPool))

	case issue.CodePatternDate:
		// A date like "2024" or "12/31/2024" is drawn from a digit pool.
		// Entropy = len(pattern digits) × log2(10), giving ≈ 3.3 bits per digit.
		digitCount := 0
		for _, r := range pattern {
			if r >= '0' && r <= '9' {
				digitCount++
			}
		}
		if digitCount == 0 {
			return 1.0
		}
		return float64(digitCount) * math.Log2(10)

	default:
		// Covered characters contribute no intrinsic entropy (maximally conservative).
		return 0.0
	}
}

// runesMatch reports whether lowerRunes[start : start+len(pat)] equals pat.
// All inputs must already be lower-cased.
func runesMatch(lowerRunes []rune, start int, pat []rune) bool {
	for i, r := range pat {
		if lowerRunes[start+i] != r {
			return false
		}
	}
	return true
}
