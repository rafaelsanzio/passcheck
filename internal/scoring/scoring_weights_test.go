package scoring

import (
	"testing"

	"github.com/rafaelsanzio/passcheck/internal/issue"
	"github.com/rafaelsanzio/passcheck/internal/passphrase"
)

func TestCalculateWithPassphrase_WithWeights(t *testing.T) {
	entropyBits := 64.0
	password := "testpassword"
	minLength := 12
	issues := IssueSet{
		Rules:      make([]issue.Issue, 2),
		Dictionary: make([]issue.Issue, 1),
	}

	// Test without weights (nil)
	scoreNil := CalculateWithPassphrase(entropyBits, password, issues, minLength, nil, nil)

	// Test with default weights (should match nil)
	wDefault := DefaultWeights()
	scoreDefault := CalculateWithPassphrase(entropyBits, password, issues, minLength, nil, &wDefault)

	if scoreNil != scoreDefault {
		t.Errorf("nil weights should match default weights: nil=%d, default=%d", scoreNil, scoreDefault)
	}

	// Test with custom weights (double dictionary penalties)
	wCustom := Weights{
		DictionaryMatch: 2.0,
	}
	scoreCustom := CalculateWithPassphrase(entropyBits, password, issues, minLength, nil, &wCustom)

	// Custom score should be lower due to doubled dictionary penalty
	if scoreCustom >= scoreNil {
		t.Errorf("doubled dictionary penalty should reduce score: custom=%d, default=%d",
			scoreCustom, scoreNil)
	}
}

func TestCalculateWithPassphrase_EntropyWeight(t *testing.T) {
	entropyBits := 64.0
	password := "testpassword"
	minLength := 12
	issues := IssueSet{}

	// Base score with default entropy weight
	wDefault := DefaultWeights()
	scoreDefault := CalculateWithPassphrase(entropyBits, password, issues, minLength, nil, &wDefault)

	// Halve entropy weight
	wHalf := Weights{
		EntropyWeight: 0.5,
	}
	scoreHalf := CalculateWithPassphrase(entropyBits, password, issues, minLength, nil, &wHalf)

	// Score should be lower with halved entropy weight
	if scoreHalf >= scoreDefault {
		t.Errorf("halved entropy weight should reduce score: half=%d, default=%d",
			scoreHalf, scoreDefault)
	}

	// Double entropy weight
	wDouble := Weights{
		EntropyWeight: 2.0,
	}
	scoreDouble := CalculateWithPassphrase(entropyBits, password, issues, minLength, nil, &wDouble)

	// Score should be higher with doubled entropy weight
	if scoreDouble <= scoreDefault {
		t.Errorf("doubled entropy weight should increase score: double=%d, default=%d",
			scoreDouble, scoreDefault)
	}
}

func TestCalculateWithPassphrase_PenaltyMultipliers(t *testing.T) {
	// Use high entropy and fewer issues to avoid clamping to 0
	entropyBits := 100.0
	password := "VeryStrongPassword123!@#" // High entropy, multiple charsets
	minLength := 12
	issues := IssueSet{
		Rules:      make([]issue.Issue, 1),
		Patterns:   make([]issue.Issue, 1),
		Dictionary: make([]issue.Issue, 1),
	}

	// Baseline with default weights
	wDefault := DefaultWeights()
	scoreDefault := CalculateWithPassphrase(entropyBits, password, issues, minLength, nil, &wDefault)

	// Double all penalties
	wDoubleAll := Weights{
		RuleViolation:  2.0,
		PatternMatch:   2.0,
		DictionaryMatch: 2.0,
	}
	scoreDoubleAll := CalculateWithPassphrase(entropyBits, password, issues, minLength, nil, &wDoubleAll)

	// Score should be significantly lower
	if scoreDoubleAll >= scoreDefault {
		t.Errorf("doubled penalties should reduce score: doubled=%d, default=%d",
			scoreDoubleAll, scoreDefault)
	}

	// Verify the reduction is meaningful
	// Default: 1*5 + 1*10 + 1*15 = 30 penalty
	// Doubled: 1*5*2 + 1*10*2 + 1*15*2 = 60 penalty
	// Difference should be 30 points
	penaltyDiff := scoreDefault - scoreDoubleAll
	if penaltyDiff < 20 { // Allow some variance due to bonuses
		t.Errorf("expected penalty difference ~30, got %d (default=%d, doubled=%d)",
			penaltyDiff, scoreDefault, scoreDoubleAll)
	}
}

func TestCalculateWithPassphrase_PassphraseWithWeights(t *testing.T) {
	entropyBits := 51.0 // Word-based entropy for 4-word passphrase
	password := "correct-horse-battery-staple"
	minLength := 12
	issues := IssueSet{
		Dictionary: make([]issue.Issue, 1), // Dictionary word detected
	}

	passphraseInfo := &passphrase.Info{
		IsPassphrase: true,
		WordCount:    4,
		Words:        []string{"correct", "horse", "battery", "staple"},
	}

	// Without weights: dictionary penalty should be 0 for passphrases
	scoreNoWeights := CalculateWithPassphrase(entropyBits, password, issues, minLength, passphraseInfo, nil)

	// With weights: dictionary penalty should still be 0 for passphrases (passphrase logic takes precedence)
	wCustom := Weights{
		DictionaryMatch: 2.0, // This should be ignored for passphrases
	}
	scoreWithWeights := CalculateWithPassphrase(entropyBits, password, issues, minLength, passphraseInfo, &wCustom)

	// Scores should be identical (dictionary penalty eliminated for passphrases regardless of weights)
	if scoreNoWeights != scoreWithWeights {
		t.Errorf("passphrase dictionary penalty should be 0 regardless of weights: noWeights=%d, withWeights=%d",
			scoreNoWeights, scoreWithWeights)
	}
}

func TestCalculateWithPassphrase_ZeroPenaltyMultiplier(t *testing.T) {
	entropyBits := 64.0
	password := "testpassword"
	minLength := 12
	issues := IssueSet{
		Rules: make([]issue.Issue, 2),
	}

	// Zero multiplier should default to 1.0
	wZero := Weights{
		RuleViolation: 0.0, // Should default to 1.0
	}
	scoreZero := CalculateWithPassphrase(entropyBits, password, issues, minLength, nil, &wZero)

	wDefault := DefaultWeights()
	scoreDefault := CalculateWithPassphrase(entropyBits, password, issues, minLength, nil, &wDefault)

	if scoreZero != scoreDefault {
		t.Errorf("zero multiplier should default to 1.0: zero=%d, default=%d",
			scoreZero, scoreDefault)
	}
}

func TestCalculateWithPassphrase_BackwardCompatibility(t *testing.T) {
	entropyBits := 64.0
	password := "testpassword"
	minLength := 12
	issues := IssueSet{
		Rules: make([]issue.Issue, 1),
	}

	// Nil weights should behave like default weights
	scoreNil := CalculateWithPassphrase(entropyBits, password, issues, minLength, nil, nil)

	wDefault := DefaultWeights()
	scoreDefault := CalculateWithPassphrase(entropyBits, password, issues, minLength, nil, &wDefault)

	if scoreNil != scoreDefault {
		t.Errorf("nil weights should match default: nil=%d, default=%d",
			scoreNil, scoreDefault)
	}
}
