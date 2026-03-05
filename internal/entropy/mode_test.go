package entropy

import (
	"testing"

	"github.com/rafaelsanzio/passcheck/internal/issue"
)

func TestCalculateWithMode_Simple(t *testing.T) {
	password := "Xk9$mP2!vR7@nL4"
	simpleEntropy := Calculate(password)
	modeEntropy := CalculateWithMode(password, "simple", nil)

	if modeEntropy != simpleEntropy {
		t.Errorf("CalculateWithMode(simple) = %.2f, want %.2f", modeEntropy, simpleEntropy)
	}
}

func TestCalculateWithMode_ReducesEntropyForPatternedPassword(t *testing.T) {
	// Both advanced and pattern-aware modes must reduce entropy below simple
	// for a password that is entirely covered by detected patterns.
	password := "qwerty123456"
	issues := []issue.Issue{
		issue.NewPattern(issue.CodePatternKeyboard, "Contains keyboard pattern: 'qwerty'", "qwerty", issue.CategoryPattern, issue.SeverityMed),
		issue.NewPattern(issue.CodePatternSequence, "Contains sequence: '123456'", "123456", issue.CategoryPattern, issue.SeverityMed),
	}

	simpleEntropy := Calculate(password)

	tests := []struct {
		mode string
	}{
		{"advanced"},
		{"pattern-aware"},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			e := CalculateWithMode(password, tt.mode, issues)
			if e >= simpleEntropy {
				t.Errorf("%s mode should reduce entropy for patterned password: simple=%.2f, got=%.2f",
					tt.mode, simpleEntropy, e)
			}
		})
	}
}

func TestCalculateWithMode_InvalidMode(t *testing.T) {
	password := "Xk9$mP2!vR7@nL4"
	simpleEntropy := Calculate(password)

	// Invalid mode should fall back to simple.
	invalidEntropy := CalculateWithMode(password, "invalid", nil)
	if invalidEntropy != simpleEntropy {
		t.Errorf("invalid mode should fall back to simple: got %.2f, want %.2f", invalidEntropy, simpleEntropy)
	}

	// Empty mode should fall back to simple.
	emptyEntropy := CalculateWithMode(password, "", nil)
	if emptyEntropy != simpleEntropy {
		t.Errorf("empty mode should fall back to simple: got %.2f, want %.2f", emptyEntropy, simpleEntropy)
	}
}

func TestCalculateWithMode_Comparison(t *testing.T) {
	// A heavily patterned password must score lower than a high-entropy random one.
	patterned := "qwerty123456"
	random := "Xk9$mP2!vR7@nL4"

	patternedIssues := []issue.Issue{
		issue.NewPattern(issue.CodePatternKeyboard, "Contains keyboard pattern: 'qwerty'", "qwerty", issue.CategoryPattern, issue.SeverityMed),
		issue.NewPattern(issue.CodePatternSequence, "Contains sequence: '123456'", "123456", issue.CategoryPattern, issue.SeverityMed),
	}

	patternedEntropy := CalculateWithMode(patterned, "advanced", patternedIssues)
	randomEntropy := CalculateWithMode(random, "advanced", nil)

	if patternedEntropy >= randomEntropy {
		t.Errorf("patterned password should have lower entropy: patterned=%.2f, random=%.2f",
			patternedEntropy, randomEntropy)
	}
}
