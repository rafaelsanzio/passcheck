package entropy

import (
	"testing"

	"github.com/rafaelsanzio/passcheck/internal/issue"
)

func TestCalculateAdvanced_NoPatterns(t *testing.T) {
	// Password with no patterns should have same entropy as simple mode
	password := "Xk9$mP2!vR7@nL4"
	simpleEntropy := Calculate(password)
	advancedEntropy := CalculateAdvanced(password, nil)

	// Should be very close (within 1% tolerance)
	tolerance := simpleEntropy * 0.01
	if advancedEntropy < simpleEntropy-tolerance || advancedEntropy > simpleEntropy+tolerance {
		t.Errorf("advanced entropy should match simple when no patterns: simple=%.2f, advanced=%.2f",
			simpleEntropy, advancedEntropy)
	}
}

func TestCalculateAdvanced_KeyboardPattern(t *testing.T) {
	// "qwerty123456" contains keyboard pattern "qwerty" and sequence "123456"
	password := "qwerty123456"
	simpleEntropy := Calculate(password)

	issues := []issue.Issue{
		issue.New(issue.CodePatternKeyboard, "Contains keyboard pattern: 'qwerty'", issue.CategoryPattern, issue.SeverityMed),
		issue.New(issue.CodePatternSequence, "Contains sequence: '123456'", issue.CategoryPattern, issue.SeverityMed),
	}

	advancedEntropy := CalculateAdvanced(password, issues)

	// Advanced entropy should be significantly lower
	if advancedEntropy >= simpleEntropy {
		t.Errorf("advanced entropy should be lower for patterned password: simple=%.2f, advanced=%.2f",
			simpleEntropy, advancedEntropy)
	}

	// Should be at least 20% reduction for this heavily patterned password
	reduction := (simpleEntropy - advancedEntropy) / simpleEntropy
	if reduction < 0.2 {
		t.Errorf("expected at least 20%% reduction, got %.1f%%", reduction*100)
	}
}

func TestCalculateAdvanced_SequencePattern(t *testing.T) {
	password := "abcd1234"
	simpleEntropy := Calculate(password)

	issues := []issue.Issue{
		issue.New(issue.CodePatternSequence, "Contains sequence: 'abcd'", issue.CategoryPattern, issue.SeverityMed),
		issue.New(issue.CodePatternSequence, "Contains sequence: '1234'", issue.CategoryPattern, issue.SeverityMed),
	}

	advancedEntropy := CalculateAdvanced(password, issues)

	if advancedEntropy >= simpleEntropy {
		t.Errorf("advanced entropy should be lower for sequence pattern: simple=%.2f, advanced=%.2f",
			simpleEntropy, advancedEntropy)
	}
}

func TestCalculateAdvanced_RepeatedBlock(t *testing.T) {
	password := "abcabc123"
	simpleEntropy := Calculate(password)

	issues := []issue.Issue{
		issue.New(issue.CodePatternBlock, "Contains repeated block: 'abc'", issue.CategoryPattern, issue.SeverityMed),
	}

	advancedEntropy := CalculateAdvanced(password, issues)

	if advancedEntropy >= simpleEntropy {
		t.Errorf("advanced entropy should be lower for repeated block: simple=%.2f, advanced=%.2f",
			simpleEntropy, advancedEntropy)
	}
}

func TestCalculateAdvanced_MinimumEntropy(t *testing.T) {
	// Even heavily patterned passwords should retain at least 10% of base entropy
	password := "qwerty123456"
	simpleEntropy := Calculate(password)

	issues := []issue.Issue{
		issue.New(issue.CodePatternKeyboard, "Contains keyboard pattern: 'qwerty'", issue.CategoryPattern, issue.SeverityMed),
		issue.New(issue.CodePatternSequence, "Contains sequence: '123456'", issue.CategoryPattern, issue.SeverityMed),
	}

	advancedEntropy := CalculateAdvanced(password, issues)
	minEntropy := simpleEntropy * 0.1

	if advancedEntropy < minEntropy {
		t.Errorf("advanced entropy should be at least 10%% of base: got %.2f, minimum %.2f",
			advancedEntropy, minEntropy)
	}
}

func TestCalculateAdvanced_EmptyPassword(t *testing.T) {
	result := CalculateAdvanced("", nil)
	if result != 0 {
		t.Errorf("expected 0 entropy for empty password, got %f", result)
	}
}

func TestCalculateAdvanced_Comparison(t *testing.T) {
	// "qwerty123456" (patterned) should have lower entropy than "Xk9$mP2!vR7@nL4" (random)
	patterned := "qwerty123456"
	random := "Xk9$mP2!vR7@nL4"

	patternedIssues := []issue.Issue{
		issue.New(issue.CodePatternKeyboard, "Contains keyboard pattern: 'qwerty'", issue.CategoryPattern, issue.SeverityMed),
		issue.New(issue.CodePatternSequence, "Contains sequence: '123456'", issue.CategoryPattern, issue.SeverityMed),
	}

	patternedEntropy := CalculateAdvanced(patterned, patternedIssues)
	randomEntropy := CalculateAdvanced(random, nil)

	if patternedEntropy >= randomEntropy {
		t.Errorf("patterned password should have lower entropy: patterned=%.2f, random=%.2f",
			patternedEntropy, randomEntropy)
	}
}

func TestAnalyzePatterns(t *testing.T) {
	password := "qwerty123456"
	issues := []issue.Issue{
		issue.New(issue.CodePatternKeyboard, "Contains keyboard pattern: 'qwerty'", issue.CategoryPattern, issue.SeverityMed),
		issue.New(issue.CodePatternSequence, "Contains sequence: '123456'", issue.CategoryPattern, issue.SeverityMed),
	}

	info := analyzePatterns(password, issues)

	// "qwerty" is 6 chars, "123456" is 6 chars, total 12 chars
	// Both patterns should cover significant portions
	if info.keyboardRatio <= 0 {
		t.Errorf("expected keyboard ratio > 0, got %.2f", info.keyboardRatio)
	}
	if info.sequenceRatio <= 0 {
		t.Errorf("expected sequence ratio > 0, got %.2f", info.sequenceRatio)
	}
	if info.totalPatternRatio <= 0 {
		t.Errorf("expected total pattern ratio > 0, got %.2f", info.totalPatternRatio)
	}
}

func TestExtractPatternFromMessage(t *testing.T) {
	tests := []struct {
		message  string
		expected string
	}{
		{"Contains keyboard pattern: 'qwerty'", "qwerty"},
		{"Contains sequence: '123456'", "123456"},
		{"Contains repeated block: 'abc'", "abc"},
		{"No pattern here", ""},
		{"Pattern: 'test'", "test"},
	}

	for _, tt := range tests {
		t.Run(tt.message, func(t *testing.T) {
			result := extractPatternFromMessage(tt.message)
			if result != tt.expected {
				t.Errorf("extractPatternFromMessage(%q) = %q, want %q", tt.message, result, tt.expected)
			}
		})
	}
}
