package scoring

import (
	"testing"

	"github.com/rafaelsanzio/passcheck/internal/issue"
)

func TestDefaultWeights(t *testing.T) {
	w := DefaultWeights()
	if w.RuleViolation != 1.0 {
		t.Errorf("RuleViolation = %f, want 1.0", w.RuleViolation)
	}
	if w.PatternMatch != 1.0 {
		t.Errorf("PatternMatch = %f, want 1.0", w.PatternMatch)
	}
	if w.DictionaryMatch != 1.0 {
		t.Errorf("DictionaryMatch = %f, want 1.0", w.DictionaryMatch)
	}
	if w.ContextMatch != 1.0 {
		t.Errorf("ContextMatch = %f, want 1.0", w.ContextMatch)
	}
	if w.HIBPBreach != 1.0 {
		t.Errorf("HIBPBreach = %f, want 1.0", w.HIBPBreach)
	}
	if w.EntropyWeight != 1.0 {
		t.Errorf("EntropyWeight = %f, want 1.0", w.EntropyWeight)
	}
}

func TestWeights_GetOrDefault(t *testing.T) {
	w := Weights{
		RuleViolation:  2.0,
		PatternMatch:   0.0, // Should default to 1.0
		DictionaryMatch: 1.5,
	}

	if w.getOrDefault(w.RuleViolation) != 2.0 {
		t.Errorf("getOrDefault(2.0) = %f, want 2.0", w.getOrDefault(w.RuleViolation))
	}
	if w.getOrDefault(w.PatternMatch) != 1.0 {
		t.Errorf("getOrDefault(0.0) = %f, want 1.0", w.getOrDefault(w.PatternMatch))
	}
	if w.getOrDefault(w.DictionaryMatch) != 1.5 {
		t.Errorf("getOrDefault(1.5) = %f, want 1.5", w.getOrDefault(w.DictionaryMatch))
	}
}

func TestWeights_ApplyWeights(t *testing.T) {
	issues := IssueSet{
		Rules:      make([]issue.Issue, 2),
		Patterns:   make([]issue.Issue, 1),
		Dictionary: make([]issue.Issue, 1),
		Context:    make([]issue.Issue, 1),
		HIBP:       make([]issue.Issue, 1),
	}

	// Default weights (all 1.0)
	w := DefaultWeights()
	// baseEntropy is already converted to score: entropyBits * maxScoreBase / entropyFull
	// For 64 bits: 64 * 100 / 128 = 50.0
	baseEntropyScore := 50.0
	base, penalty := w.applyWeights(baseEntropyScore, issues, PenaltyPerDictMatch)

	// Base should be unchanged with default entropy weight
	expectedBase := 50.0
	if base != expectedBase {
		t.Errorf("base = %.2f, want %.2f", base, expectedBase)
	}

	// Penalty should be: 2*5 + 1*10 + 1*15 + 1*20 + 1*25 = 80
	expectedPenalty := 2*PenaltyPerRule + 1*PenaltyPerPattern + 1*PenaltyPerDictMatch + 1*PenaltyPerContext + 1*PenaltyPerHIBP
	if penalty != expectedPenalty {
		t.Errorf("penalty = %d, want %d", penalty, expectedPenalty)
	}
}

func TestWeights_ApplyWeights_CustomMultipliers(t *testing.T) {
	issues := IssueSet{
		Rules:      make([]issue.Issue, 2),
		Patterns:   make([]issue.Issue, 1),
		Dictionary: make([]issue.Issue, 1),
	}

	// Custom weights: double dictionary penalties, halve entropy
	w := Weights{
		DictionaryMatch: 2.0,
		EntropyWeight:   0.5,
	}

	// baseEntropy is already converted to score: 64 bits → 50.0 score
	baseEntropyScore := 50.0
	base, penalty := w.applyWeights(baseEntropyScore, issues, PenaltyPerDictMatch)

	// Base should be halved: 50.0 * 0.5 = 25.0
	expectedBase := 25.0
	if base != expectedBase {
		t.Errorf("base = %.2f, want %.2f", base, expectedBase)
	}

	// Dictionary penalty should be doubled: 1 * 15 * 2.0 = 30
	// Other penalties unchanged: 2*5 + 1*10 = 20
	expectedPenalty := 2*PenaltyPerRule + 1*PenaltyPerPattern + int(float64(1*PenaltyPerDictMatch)*2.0)
	if penalty != expectedPenalty {
		t.Errorf("penalty = %d, want %d", penalty, expectedPenalty)
	}
}

func TestWeights_ZeroValuesDefaultToOne(t *testing.T) {
	issues := IssueSet{
		Rules: make([]issue.Issue, 1),
	}

	// Zero values should default to 1.0
	w := Weights{} // All zeros
	baseEntropyScore := 50.0 // Already converted to score
	base, penalty := w.applyWeights(baseEntropyScore, issues, PenaltyPerDictMatch)

	// Should behave like default weights
	wDefault := DefaultWeights()
	baseDefault, penaltyDefault := wDefault.applyWeights(baseEntropyScore, issues, PenaltyPerDictMatch)

	if base != baseDefault {
		t.Errorf("zero weights base = %.2f, default = %.2f (should match)", base, baseDefault)
	}
	if penalty != penaltyDefault {
		t.Errorf("zero weights penalty = %d, default = %d (should match)", penalty, penaltyDefault)
	}
}
