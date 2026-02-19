// Package entropy implements password entropy calculation.
//
// This file provides Markov-chain analysis for character transition probabilities
// to estimate entropy more accurately by considering how characters typically
// follow each other in real passwords.

package entropy

import (
	"unicode"

	"github.com/rafaelsanzio/passcheck/internal/issue"
)

// CalculatePatternAware calculates entropy using pattern-aware adjustments
// plus Markov-chain analysis for character transition probabilities.
func CalculatePatternAware(password string, patternIssues []issue.Issue) float64 {
	// Start with advanced pattern-aware entropy
	patternEntropy := CalculateAdvanced(password, patternIssues)
	if patternEntropy == 0 {
		return 0
	}

	// Apply Markov-chain adjustment
	markovAdjustment := calculateMarkovAdjustment(password)

	// Combine: pattern entropy adjusted by Markov analysis
	// Markov adjustment is multiplicative (0.5 to 1.5 range)
	finalEntropy := patternEntropy * markovAdjustment

	// Ensure we don't go below minimum
	minEntropy := patternEntropy * 0.05 // At least 5% of pattern entropy
	if finalEntropy < minEntropy {
		finalEntropy = minEntropy
	}

	return finalEntropy
}

// calculateMarkovAdjustment calculates a multiplicative adjustment factor
// based on character transition probabilities. Returns a value between
// 0.5 (very predictable transitions) and 1.5 (very unpredictable transitions).
func calculateMarkovAdjustment(password string) float64 {
	runes := []rune(password)
	if len(runes) < 2 {
		return 1.0 // No transitions to analyze
	}

	// Analyze character transitions
	transitions := analyzeTransitions(runes)

	// Calculate predictability score (0.0 = very predictable, 1.0 = very unpredictable)
	predictability := calculatePredictability(transitions)

	// Convert predictability to adjustment factor
	// Low predictability (predictable) → lower adjustment (0.5-1.0)
	// High predictability (unpredictable) → higher adjustment (1.0-1.5)
	adjustment := 0.5 + (predictability * 1.0)

	return adjustment
}

// transitionInfo holds information about character transitions.
type transitionInfo struct {
	// Character type transitions (letter→letter, digit→digit, etc.)
	sameTypeTransitions int
	mixedTypeTransitions int
	totalTransitions int

	// Case transitions (lower→upper, upper→lower)
	caseTransitions int

	// Repetition (same character repeated)
	repetitions int
}

// analyzeTransitions analyzes character transitions in the password.
func analyzeTransitions(runes []rune) transitionInfo {
	var info transitionInfo
	info.totalTransitions = len(runes) - 1

	for i := 1; i < len(runes); i++ {
		prev := runes[i-1]
		curr := runes[i]

		// Check for repetition
		if prev == curr {
			info.repetitions++
			continue
		}

		// Check character type transitions
		prevIsLetter := unicode.IsLetter(prev)
		prevIsDigit := unicode.IsDigit(prev)
		prevIsUpper := unicode.IsUpper(prev)
		prevIsLower := unicode.IsLower(prev)

		currIsLetter := unicode.IsLetter(curr)
		currIsDigit := unicode.IsDigit(curr)
		currIsUpper := unicode.IsUpper(curr)
		currIsLower := unicode.IsLower(curr)

		// Same type transition
		if (prevIsLetter && currIsLetter) || (prevIsDigit && currIsDigit) ||
			(!prevIsLetter && !prevIsDigit && !currIsLetter && !currIsDigit) {
			info.sameTypeTransitions++
		} else {
			info.mixedTypeTransitions++
		}

		// Case transitions (only for letters)
		if prevIsLetter && currIsLetter {
			if (prevIsLower && currIsUpper) || (prevIsUpper && currIsLower) {
				info.caseTransitions++
			}
		}
	}

	return info
}

// calculatePredictability calculates how predictable the password is based on transitions.
// Returns a value between 0.0 (very predictable) and 1.0 (very unpredictable).
func calculatePredictability(info transitionInfo) float64 {
	if info.totalTransitions == 0 {
		return 0.5 // Neutral for single character
	}

	// High repetition → low predictability score (more predictable = bad)
	repetitionRatio := float64(info.repetitions) / float64(info.totalTransitions)
	repetitionScore := 1.0 - (repetitionRatio * 2.0) // Penalize heavily
	if repetitionScore < 0 {
		repetitionScore = 0
	}

	// Mixed type transitions → higher predictability score (less predictable = good)
	mixedRatio := float64(info.mixedTypeTransitions) / float64(info.totalTransitions)
	mixedScore := mixedRatio * 1.5 // Reward mixed types
	if mixedScore > 1.0 {
		mixedScore = 1.0
	}

	// Case transitions → higher predictability score (less predictable = good)
	caseRatio := float64(info.caseTransitions) / float64(info.totalTransitions)
	caseScore := caseRatio * 1.2 // Reward case mixing
	if caseScore > 1.0 {
		caseScore = 1.0
	}

	// Combine scores with weights
	// Repetition is most important (40%), mixed types (35%), case (25%)
	predictability := (repetitionScore * 0.4) + (mixedScore * 0.35) + (caseScore * 0.25)

	// Ensure result is in [0.0, 1.0] range
	if predictability < 0 {
		predictability = 0
	}
	if predictability > 1.0 {
		predictability = 1.0
	}

	return predictability
}
