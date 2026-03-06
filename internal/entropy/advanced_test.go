package entropy

import (
	"testing"

	"github.com/rafaelsanzio/passcheck/internal/issue"
)

func TestCalculateAdvanced_NoPatterns(t *testing.T) {
	// No patterns → all characters are free → result equals simple entropy.
	password := "Xk9$mP2!vR7@nL4"
	simpleEntropy := Calculate(password)
	advancedEntropy := CalculateAdvanced(password, nil)

	tolerance := simpleEntropy * 0.01 // 1% tolerance for floating-point rounding
	if advancedEntropy < simpleEntropy-tolerance || advancedEntropy > simpleEntropy+tolerance {
		t.Errorf("advanced entropy should equal simple when no patterns: simple=%.2f, advanced=%.2f",
			simpleEntropy, advancedEntropy)
	}
}

func TestCalculateAdvanced_KeyboardPattern(t *testing.T) {
	// "qwerty123456" is entirely covered by a keyboard walk and a sequence.
	password := "qwerty123456"
	simpleEntropy := Calculate(password)

	issues := []issue.Issue{
		issue.NewPattern(issue.CodePatternKeyboard, "Contains keyboard pattern: 'qwerty'", "qwerty", issue.CategoryPattern, issue.SeverityMed),
		issue.NewPattern(issue.CodePatternSequence, "Contains sequence: '123456'", "123456", issue.CategoryPattern, issue.SeverityMed),
	}

	advancedEntropy := CalculateAdvanced(password, issues)

	if advancedEntropy >= simpleEntropy {
		t.Errorf("advanced entropy should be lower for patterned password: simple=%.2f, advanced=%.2f",
			simpleEntropy, advancedEntropy)
	}

	// Intrinsic entropy for both patterns is ≈ 14 bits vs ≈ 62 bits simple.
	reduction := (simpleEntropy - advancedEntropy) / simpleEntropy
	if reduction < 0.2 {
		t.Errorf("expected at least 20%% reduction, got %.1f%%", reduction*100)
	}
}

func TestCalculateAdvanced_SequencePattern(t *testing.T) {
	password := "abcd1234"
	simpleEntropy := Calculate(password)

	issues := []issue.Issue{
		issue.NewPattern(issue.CodePatternSequence, "Contains sequence: 'abcd'", "abcd", issue.CategoryPattern, issue.SeverityMed),
		issue.NewPattern(issue.CodePatternSequence, "Contains sequence: '1234'", "1234", issue.CategoryPattern, issue.SeverityMed),
	}

	advancedEntropy := CalculateAdvanced(password, issues)

	if advancedEntropy >= simpleEntropy {
		t.Errorf("advanced entropy should be lower for sequence pattern: simple=%.2f, advanced=%.2f",
			simpleEntropy, advancedEntropy)
	}
}

func TestCalculateAdvanced_RepeatedBlock(t *testing.T) {
	// "abcabc" covered by repeated block; "123" is free.
	password := "abcabc123"
	simpleEntropy := Calculate(password)

	issues := []issue.Issue{
		issue.NewPattern(issue.CodePatternBlock, "Contains repeated block: 'abc'", "abc", issue.CategoryPattern, issue.SeverityMed),
	}

	advancedEntropy := CalculateAdvanced(password, issues)

	if advancedEntropy >= simpleEntropy {
		t.Errorf("advanced entropy should be lower for repeated block: simple=%.2f, advanced=%.2f",
			simpleEntropy, advancedEntropy)
	}
}

func TestCalculateAdvanced_RepeatedBlock_SecondOccurrenceAddsNoEntropy(t *testing.T) {
	// "abcabc" should contribute entropy for one copy of "abc" only.
	// "abc123abc" covers positions 0-2 and 6-8 with the same block.
	password := "abc123abc"

	issues := []issue.Issue{
		issue.NewPattern(issue.CodePatternBlock, "Contains repeated block: 'abc'", "abc", issue.CategoryPattern, issue.SeverityMed),
	}

	e := CalculateAdvanced(password, issues)
	if e <= 0 {
		t.Errorf("expected positive entropy, got %.2f", e)
	}

	// The two "abc" occurrences together must not exceed what three independent
	// free occurrences would give (a deliberately loose upper bound).
	simpleForBlock := 3 * Calculate("abc") // three independent copies would be 3× simple("abc")
	if e >= simpleForBlock {
		t.Errorf("two block occurrences should not exceed single-copy entropy: e=%.2f, single=%.2f",
			e, simpleForBlock)
	}
}

func TestCalculateAdvanced_IssuesWithoutPattern_Ignored(t *testing.T) {
	// Issues created via issue.New (no Pattern field) must be silently skipped;
	// the result should equal simple entropy.
	password := "qwerty123456"
	simpleEntropy := Calculate(password)

	legacyIssues := []issue.Issue{
		issue.New(issue.CodePatternKeyboard, "Contains keyboard pattern: 'qwerty'", issue.CategoryPattern, issue.SeverityMed),
	}

	advancedEntropy := CalculateAdvanced(password, legacyIssues)

	tolerance := simpleEntropy * 0.01
	if advancedEntropy < simpleEntropy-tolerance || advancedEntropy > simpleEntropy+tolerance {
		t.Errorf("issues without Pattern field should not reduce entropy: simple=%.2f, advanced=%.2f",
			simpleEntropy, advancedEntropy)
	}
}

func TestCalculateAdvanced_MinimumEntropy(t *testing.T) {
	// Even a fully-patterned password retains positive (non-zero) entropy
	// because each pattern class has a non-trivial intrinsic search space.
	password := "qwerty123456"
	simpleEntropy := Calculate(password)

	issues := []issue.Issue{
		issue.NewPattern(issue.CodePatternKeyboard, "Contains keyboard pattern: 'qwerty'", "qwerty", issue.CategoryPattern, issue.SeverityMed),
		issue.NewPattern(issue.CodePatternSequence, "Contains sequence: '123456'", "123456", issue.CategoryPattern, issue.SeverityMed),
	}

	advancedEntropy := CalculateAdvanced(password, issues)

	if advancedEntropy <= 0 {
		t.Errorf("advanced entropy should be positive even for patterned password, got %.2f", advancedEntropy)
	}
	if advancedEntropy >= simpleEntropy {
		t.Errorf("advanced entropy must be below simple for this patterned password: advanced=%.2f, simple=%.2f",
			advancedEntropy, simpleEntropy)
	}
}

func TestCalculateAdvanced_EmptyPassword(t *testing.T) {
	result := CalculateAdvanced("", nil)
	if result != 0 {
		t.Errorf("expected 0 entropy for empty password, got %f", result)
	}
}

// ---------------------------------------------------------------------------
// intrinsicPatternEntropy
// ---------------------------------------------------------------------------

func TestIntrinsicPatternEntropy_Keyboard(t *testing.T) {
	e := intrinsicPatternEntropy(issue.CodePatternKeyboard, "qwerty")
	// log2(150) ≈ 7.23 bits
	if e < 7.0 || e > 8.0 {
		t.Errorf("keyboard intrinsic entropy out of expected range [7,8]: got %.2f", e)
	}
}

func TestIntrinsicPatternEntropy_Sequence(t *testing.T) {
	e := intrinsicPatternEntropy(issue.CodePatternSequence, "1234")
	// log2(144) ≈ 7.17 bits
	if e < 7.0 || e > 8.0 {
		t.Errorf("sequence intrinsic entropy out of expected range [7,8]: got %.2f", e)
	}
}

func TestIntrinsicPatternEntropy_Block(t *testing.T) {
	// "abc" (3 lower chars): 3 × log2(26) ≈ 14.1 bits
	e := intrinsicPatternEntropy(issue.CodePatternBlock, "abc")
	if e < 14.0 || e > 15.0 {
		t.Errorf("block intrinsic entropy for 'abc' out of expected range [14,15]: got %.2f", e)
	}
}

func TestIntrinsicPatternEntropy_Unknown(t *testing.T) {
	// Unknown codes return 0 (no reduction applied).
	e := intrinsicPatternEntropy("UNKNOWN_CODE", "xyz")
	if e != 0.0 {
		t.Errorf("unknown pattern code should return 0, got %.2f", e)
	}
}
