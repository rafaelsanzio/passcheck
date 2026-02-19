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

func TestCalculateWithMode_Advanced(t *testing.T) {
	password := "qwerty123456"
	issues := []issue.Issue{
		issue.New(issue.CodePatternKeyboard, "Contains keyboard pattern: 'qwerty'", issue.CategoryPattern, issue.SeverityMed),
		issue.New(issue.CodePatternSequence, "Contains sequence: '123456'", issue.CategoryPattern, issue.SeverityMed),
	}

	simpleEntropy := Calculate(password)
	advancedEntropy := CalculateWithMode(password, "advanced", issues)

	if advancedEntropy >= simpleEntropy {
		t.Errorf("advanced mode should reduce entropy: simple=%.2f, advanced=%.2f",
			simpleEntropy, advancedEntropy)
	}
}

func TestCalculateWithMode_PatternAware(t *testing.T) {
	password := "qwerty123456"
	issues := []issue.Issue{
		issue.New(issue.CodePatternKeyboard, "Contains keyboard pattern: 'qwerty'", issue.CategoryPattern, issue.SeverityMed),
		issue.New(issue.CodePatternSequence, "Contains sequence: '123456'", issue.CategoryPattern, issue.SeverityMed),
	}

	simpleEntropy := Calculate(password)
	patternAwareEntropy := CalculateWithMode(password, "pattern-aware", issues)

	if patternAwareEntropy >= simpleEntropy {
		t.Errorf("pattern-aware mode should reduce entropy: simple=%.2f, pattern-aware=%.2f",
			simpleEntropy, patternAwareEntropy)
	}
}

func TestCalculateWithMode_InvalidMode(t *testing.T) {
	password := "Xk9$mP2!vR7@nL4"
	simpleEntropy := Calculate(password)

	// Invalid mode should fall back to simple
	invalidEntropy := CalculateWithMode(password, "invalid", nil)
	if invalidEntropy != simpleEntropy {
		t.Errorf("invalid mode should fall back to simple: got %.2f, want %.2f", invalidEntropy, simpleEntropy)
	}

	// Empty mode should fall back to simple
	emptyEntropy := CalculateWithMode(password, "", nil)
	if emptyEntropy != simpleEntropy {
		t.Errorf("empty mode should fall back to simple: got %.2f, want %.2f", emptyEntropy, simpleEntropy)
	}
}

func TestCalculateWithMode_Comparison(t *testing.T) {
	// Test that "qwerty123456" has lower entropy than "Xk9$mP2!vR7@nL4" in advanced mode
	patterned := "qwerty123456"
	random := "Xk9$mP2!vR7@nL4"

	patternedIssues := []issue.Issue{
		issue.New(issue.CodePatternKeyboard, "Contains keyboard pattern: 'qwerty'", issue.CategoryPattern, issue.SeverityMed),
		issue.New(issue.CodePatternSequence, "Contains sequence: '123456'", issue.CategoryPattern, issue.SeverityMed),
	}

	patternedEntropy := CalculateWithMode(patterned, "advanced", patternedIssues)
	randomEntropy := CalculateWithMode(random, "advanced", nil)

	if patternedEntropy >= randomEntropy {
		t.Errorf("patterned password should have lower entropy: patterned=%.2f, random=%.2f",
			patternedEntropy, randomEntropy)
	}
}
