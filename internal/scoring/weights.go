// Package scoring implements the password strength scoring algorithm.
//
// This file provides weight application logic for customizable penalty multipliers.

package scoring

// Weights holds penalty multipliers and entropy weight for customizable scoring.
// Zero values are treated as defaults (1.0).
type Weights struct {
	RuleViolation  float64 // Multiplier for rule violation penalties
	PatternMatch   float64 // Multiplier for pattern detection penalties
	DictionaryMatch float64 // Multiplier for dictionary match penalties
	ContextMatch   float64 // Multiplier for context detection penalties
	HIBPBreach     float64 // Multiplier for HIBP breach penalties
	EntropyWeight  float64 // Multiplier for entropy base score
}

// DefaultWeights returns weights with all multipliers set to 1.0 (default behavior).
func DefaultWeights() Weights {
	return Weights{
		RuleViolation:  1.0,
		PatternMatch:   1.0,
		DictionaryMatch: 1.0,
		ContextMatch:   1.0,
		HIBPBreach:     1.0,
		EntropyWeight:  1.0,
	}
}

// getOrDefault returns the weight value, or 1.0 if zero (default).
func (w Weights) getOrDefault(field float64) float64 {
	if field == 0 {
		return 1.0
	}
	return field
}

// applyWeights applies weight multipliers to penalties and entropy base score.
func (w Weights) applyWeights(baseEntropy float64, issues IssueSet, dictPenaltyPerIssue int) (weightedBase float64, weightedPenalty int) {
	// Apply entropy weight to base score
	entropyWeight := w.getOrDefault(w.EntropyWeight)
	weightedBase = baseEntropy * entropyWeight

	// Apply penalty multipliers
	ruleWeight := w.getOrDefault(w.RuleViolation)
	patternWeight := w.getOrDefault(w.PatternMatch)
	dictWeight := w.getOrDefault(w.DictionaryMatch)
	contextWeight := w.getOrDefault(w.ContextMatch)
	hibpWeight := w.getOrDefault(w.HIBPBreach)

	weightedPenalty = int(float64(len(issues.Rules))*PenaltyPerRule*ruleWeight +
		float64(len(issues.Patterns))*PenaltyPerPattern*patternWeight +
		float64(len(issues.Dictionary))*float64(dictPenaltyPerIssue)*dictWeight +
		float64(len(issues.Context))*PenaltyPerContext*contextWeight +
		float64(len(issues.HIBP))*PenaltyPerHIBP*hibpWeight)

	return weightedBase, weightedPenalty
}
