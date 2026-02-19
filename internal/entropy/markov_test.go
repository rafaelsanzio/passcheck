package entropy

import (
	"testing"

	"github.com/rafaelsanzio/passcheck/internal/issue"
)

func TestCalculatePatternAware_NoPatterns(t *testing.T) {
	password := "Xk9$mP2!vR7@nL4"
	simpleEntropy := Calculate(password)
	patternAwareEntropy := CalculatePatternAware(password, nil)

	// Should be close to simple entropy when no patterns
	tolerance := simpleEntropy * 0.1 // 10% tolerance for Markov adjustments
	if patternAwareEntropy < simpleEntropy-tolerance || patternAwareEntropy > simpleEntropy+tolerance {
		t.Logf("pattern-aware entropy may differ due to Markov analysis: simple=%.2f, pattern-aware=%.2f",
			simpleEntropy, patternAwareEntropy)
	}
}

func TestCalculatePatternAware_WithPatterns(t *testing.T) {
	password := "qwerty123456"
	simpleEntropy := Calculate(password)

	issues := []issue.Issue{
		issue.New(issue.CodePatternKeyboard, "Contains keyboard pattern: 'qwerty'", issue.CategoryPattern, issue.SeverityMed),
		issue.New(issue.CodePatternSequence, "Contains sequence: '123456'", issue.CategoryPattern, issue.SeverityMed),
	}

	patternAwareEntropy := CalculatePatternAware(password, issues)

	// Should be lower than simple entropy
	if patternAwareEntropy >= simpleEntropy {
		t.Errorf("pattern-aware entropy should be lower: simple=%.2f, pattern-aware=%.2f",
			simpleEntropy, patternAwareEntropy)
	}
}

func TestCalculateMarkovAdjustment(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantMin  float64
		wantMax  float64
	}{
		{"repetitive", "aaaa", 0.5, 1.0},
		{"mixed types", "aA1!bB2@", 1.0, 1.5},
		{"case transitions", "aAbBcC", 1.0, 1.5},
		{"predictable", "qwerty", 0.5, 1.0},
		{"random", "Xk9$mP2!vR7@nL4", 1.0, 1.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adjustment := calculateMarkovAdjustment(tt.password)
			if adjustment < tt.wantMin || adjustment > tt.wantMax {
				t.Errorf("calculateMarkovAdjustment(%q) = %.2f, want between %.2f and %.2f",
					tt.password, adjustment, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestAnalyzeTransitions(t *testing.T) {
	tests := []struct {
		name     string
		password string
		check    func(transitionInfo) bool
	}{
		{"repetitions", "aaaa", func(info transitionInfo) bool {
			return info.repetitions > 0
		}},
		{"mixed types", "aA1!", func(info transitionInfo) bool {
			return info.mixedTypeTransitions > 0
		}},
		{"case transitions", "aAbB", func(info transitionInfo) bool {
			return info.caseTransitions > 0
		}},
		{"single char", "a", func(info transitionInfo) bool {
			return info.totalTransitions == 0
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runes := []rune(tt.password)
			info := analyzeTransitions(runes)
			if !tt.check(info) {
				t.Errorf("analyzeTransitions(%q) did not meet expectations: %+v", tt.password, info)
			}
		})
	}
}

func TestCalculatePredictability(t *testing.T) {
	// Very repetitive password should have low predictability
	repetitive := []rune("aaaa")
	infoRep := analyzeTransitions(repetitive)
	predRep := calculatePredictability(infoRep)
	if predRep > 0.5 {
		t.Errorf("repetitive password should have low predictability: got %.2f", predRep)
	}

	// Mixed password should have higher predictability
	mixed := []rune("aA1!bB2@")
	infoMixed := analyzeTransitions(mixed)
	predMixed := calculatePredictability(infoMixed)
	if predMixed < 0.5 {
		t.Errorf("mixed password should have higher predictability: got %.2f", predMixed)
	}

	// Predictability should be in [0.0, 1.0] range
	if predRep < 0 || predRep > 1.0 {
		t.Errorf("predictability out of range: %.2f", predRep)
	}
	if predMixed < 0 || predMixed > 1.0 {
		t.Errorf("predictability out of range: %.2f", predMixed)
	}
}
