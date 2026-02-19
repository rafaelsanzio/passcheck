// Package entropy implements password entropy calculation.
//
// This file provides pattern-aware entropy calculation that reduces entropy
// for detected patterns (keyboard walks, sequences, repeated blocks) to
// provide more accurate strength estimates.

package entropy

import (
	"strings"

	"github.com/rafaelsanzio/passcheck/internal/issue"
)

// CalculateAdvanced calculates entropy with pattern-aware adjustments.
// It starts with the simple entropy calculation and then reduces it based
// on detected patterns (keyboard walks, sequences, repeated blocks).
func CalculateAdvanced(password string, patternIssues []issue.Issue) float64 {
	// Start with simple entropy calculation
	baseEntropy := Calculate(password)
	if baseEntropy == 0 {
		return 0
	}

	// Extract pattern information from issues
	patternInfo := analyzePatterns(password, patternIssues)

	// Calculate reduction factor based on patterns
	reductionFactor := calculatePatternReduction(patternInfo)

	// Apply reduction: entropy = base × (1 - reduction)
	adjustedEntropy := baseEntropy * (1.0 - reductionFactor)

	// Ensure entropy doesn't go below a minimum threshold
	// (at least 10% of base entropy to avoid zero/negative)
	minEntropy := baseEntropy * 0.1
	if adjustedEntropy < minEntropy {
		adjustedEntropy = minEntropy
	}

	return adjustedEntropy
}

// patternInfo holds information about detected patterns in a password.
type patternInfo struct {
	keyboardRatio    float64 // ratio of password covered by keyboard patterns
	sequenceRatio    float64 // ratio of password covered by sequences
	repeatedRatio    float64 // ratio of password covered by repeated blocks
	totalPatternRatio float64 // total ratio covered by any pattern
}

// analyzePatterns extracts pattern information from detected issues.
func analyzePatterns(password string, issues []issue.Issue) patternInfo {
	runes := []rune(password)
	if len(runes) == 0 {
		return patternInfo{}
	}

	// Track which positions are covered by patterns
	covered := make([]bool, len(runes))

	var keyboardCount, sequenceCount, repeatedCount int

	for _, iss := range issues {
		// Extract pattern from issue message
		pattern := extractPatternFromMessage(iss.Message)
		if pattern == "" {
			continue
		}

		// Find all occurrences of this pattern in the password (case-insensitive)
		lowerPassword := strings.ToLower(password)
		lowerPattern := strings.ToLower(pattern)
		start := 0

		for {
			idx := strings.Index(lowerPassword[start:], lowerPattern)
			if idx == -1 {
				break
			}
			actualIdx := start + idx
			end := actualIdx + len([]rune(pattern))

			// Mark positions as covered
			for i := actualIdx; i < end && i < len(runes); i++ {
				covered[i] = true
			}

			// Count by pattern type
			switch iss.Code {
			case issue.CodePatternKeyboard:
				keyboardCount += len([]rune(pattern))
			case issue.CodePatternSequence:
				sequenceCount += len([]rune(pattern))
			case issue.CodePatternBlock:
				repeatedCount += len([]rune(pattern))
			}

			start = actualIdx + 1
		}
	}

	// Calculate ratios
	totalLen := float64(len(runes))
	keyboardRatio := float64(keyboardCount) / totalLen
	sequenceRatio := float64(sequenceCount) / totalLen
	repeatedRatio := float64(repeatedCount) / totalLen

	// Count total covered positions
	totalCovered := 0
	for _, c := range covered {
		if c {
			totalCovered++
		}
	}
	totalPatternRatio := float64(totalCovered) / totalLen

	return patternInfo{
		keyboardRatio:    keyboardRatio,
		sequenceRatio:    sequenceRatio,
		repeatedRatio:    repeatedRatio,
		totalPatternRatio: totalPatternRatio,
	}
}

// extractPatternFromMessage extracts the pattern string from an issue message.
// Messages are formatted like: "Contains keyboard pattern: 'qwerty'"
func extractPatternFromMessage(message string) string {
	// Look for pattern in quotes
	start := strings.Index(message, "'")
	if start == -1 {
		return ""
	}
	end := strings.LastIndex(message, "'")
	if end <= start {
		return ""
	}
	return message[start+1 : end]
}

// calculatePatternReduction calculates the entropy reduction factor based on patterns.
// Returns a value between 0.0 (no reduction) and 0.9 (maximum reduction).
func calculatePatternReduction(info patternInfo) float64 {
	// Base reduction from total pattern coverage
	// More patterns = more reduction, but with diminishing returns
	baseReduction := info.totalPatternRatio * 0.6 // Up to 60% reduction

	// Additional reduction for specific pattern types
	// Keyboard patterns are more predictable than sequences
	keyboardPenalty := info.keyboardRatio * 0.15 // Up to 15% additional
	sequencePenalty := info.sequenceRatio * 0.10  // Up to 10% additional
	repeatedPenalty := info.repeatedRatio * 0.20  // Up to 20% additional (very predictable)

	// Combine reductions (with diminishing returns)
	totalReduction := baseReduction + keyboardPenalty + sequencePenalty + repeatedPenalty

	// Cap maximum reduction at 90% (always keep at least 10% of entropy)
	if totalReduction > 0.9 {
		totalReduction = 0.9
	}

	return totalReduction
}
