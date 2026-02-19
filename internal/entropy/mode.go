// Package entropy implements password entropy calculation.
//
// This file provides mode selection logic for different entropy calculation methods.

package entropy

import (
	"github.com/rafaelsanzio/passcheck/internal/issue"
)

// Mode represents the entropy calculation mode.
type Mode string

const (
	// ModeSimple uses the basic character-pool × length formula.
	ModeSimple Mode = "simple"

	// ModeAdvanced reduces entropy for detected patterns.
	ModeAdvanced Mode = "advanced"

	// ModePatternAware includes pattern analysis plus Markov-chain analysis.
	ModePatternAware Mode = "pattern-aware"
)

// CalculateWithMode calculates entropy using the specified mode.
// If mode is empty or invalid, falls back to simple mode.
func CalculateWithMode(password string, mode string, patternIssues []issue.Issue) float64 {
	switch Mode(mode) {
	case ModeAdvanced:
		return CalculateAdvanced(password, patternIssues)
	case ModePatternAware:
		return CalculatePatternAware(password, patternIssues)
	default:
		return Calculate(password)
	}
}
