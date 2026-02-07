package feedback

import (
	"strings"
	"testing"

	"github.com/rafaelsanzio/passcheck/internal/issue"
	"github.com/rafaelsanzio/passcheck/internal/scoring"
)

// ---------------------------------------------------------------------------
// Refine (integration)
// ---------------------------------------------------------------------------

func TestRefine_Empty(t *testing.T) {
	result := Refine(scoring.IssueSet{}, DefaultMaxIssues)
	if len(result) != 0 {
		t.Errorf("expected 0 issues, got %d: %v", len(result), result)
	}
}

func TestRefine_SortsBySeverity(t *testing.T) {
	issues := scoring.IssueSet{
		Rules:      []issue.Issue{issue.New(issue.CodeRuleNoUpper, "Add at least one uppercase letter", issue.CategoryRule, issue.SeverityLow)},
		Patterns:   []issue.Issue{issue.New(issue.CodePatternSequence, "Contains sequence: 'abcd'", issue.CategoryPattern, issue.SeverityMed)},
		Dictionary: []issue.Issue{issue.New(issue.CodeDictCommonPassword, "This password appears in common password lists", issue.CategoryDictionary, issue.SeverityHigh)},
		Context:    []issue.Issue{issue.New(issue.CodeContextWord, "Contains personal information: \"john\"", issue.CategoryContext, issue.SeverityHigh)},
	}
	result := Refine(issues, 0)
	if len(result) < 4 {
		t.Fatalf("expected 4 issues (dict, context, pattern, rule), got %d", len(result))
	}
	assertContains(t, result[0].Message, "password lists")
	assertContains(t, result[1].Message, "personal information")
	assertContains(t, result[2].Message, "sequence")
	assertContains(t, result[3].Message, "uppercase")
}

func TestRefine_HIBP_FirstInOrder(t *testing.T) {
	// buildRanked orders: HIBP, Dictionary, Context, Patterns, Rules.
	// HIBP issues must be included and appear first when present.
	issues := scoring.IssueSet{
		HIBP:       []issue.Issue{issue.New(issue.CodeHIBPBreached, "Password has been found in a data breach.", issue.CategoryBreach, issue.SeverityHigh)},
		Rules:      []issue.Issue{issue.New(issue.CodeRuleTooShort, "Too short", issue.CategoryRule, issue.SeverityLow)},
		Dictionary: []issue.Issue{issue.New(issue.CodeDictCommonPassword, "Common password", issue.CategoryDictionary, issue.SeverityHigh)},
	}
	result := Refine(issues, 0)
	if len(result) < 3 {
		t.Fatalf("expected at least 3 issues (HIBP, dict, rule), got %d", len(result))
	}
	if result[0].Code != issue.CodeHIBPBreached {
		t.Errorf("first issue should be HIBP (buildRanked order), got Code=%q", result[0].Code)
	}
	assertContains(t, result[0].Message, "data breach")
}

func TestRefine_Dedup(t *testing.T) {
	issues := scoring.IssueSet{
		Patterns:   []issue.Issue{issue.New(issue.CodePatternSubstitution, "Contains common word with substitution: 'sunshine'", issue.CategoryPattern, issue.SeverityMed)},
		Dictionary: []issue.Issue{issue.New(issue.CodeDictCommonWord, "Contains common word: 'sunshine'", issue.CategoryDictionary, issue.SeverityHigh)},
	}
	result := Refine(issues, 0)
	if len(result) != 1 {
		t.Errorf("expected 1 issue after dedup, got %d: %v", len(result), result)
	}
	if len(result) > 0 {
		assertContains(t, result[0].Message, "common word: 'sunshine'")
	}
}

func TestRefine_DedupKeepsHighestSeverity(t *testing.T) {
	issues := scoring.IssueSet{
		Rules:      []issue.Issue{issue.New(issue.CodeRuleRepeatedChars, "Avoid repeating character 'aaa'", issue.CategoryRule, issue.SeverityLow)},
		Patterns:   []issue.Issue{issue.New(issue.CodePatternBlock, "Contains repeated block: 'aaa'", issue.CategoryPattern, issue.SeverityMed)},
		Dictionary: []issue.Issue{issue.New(issue.CodeDictCommonWord, "Contains common word: 'aaa'", issue.CategoryDictionary, issue.SeverityHigh)},
	}
	result := Refine(issues, 0)
	if len(result) != 1 {
		t.Errorf("expected 1 issue, got %d: %v", len(result), result)
	}
	if len(result) > 0 {
		assertContains(t, result[0].Message, "common word")
	}
}

func TestRefine_UnquotedMessagesNeverDeduped(t *testing.T) {
	issues := scoring.IssueSet{
		Dictionary: []issue.Issue{
			issue.New(issue.CodeDictCommonPassword, "This password appears in common password lists", issue.CategoryDictionary, issue.SeverityHigh),
			issue.New(issue.CodeDictLeetVariant, "This is a leetspeak variant of a common password", issue.CategoryDictionary, issue.SeverityHigh),
		},
	}
	result := Refine(issues, 0)
	if len(result) != 2 {
		t.Errorf("expected 2 issues (unquoted), got %d: %v", len(result), result)
	}
}

func TestRefine_Limit(t *testing.T) {
	issues := scoring.IssueSet{
		Rules: []issue.Issue{
			issue.New(issue.CodeRuleTooShort, "r1", issue.CategoryRule, issue.SeverityLow),
			issue.New(issue.CodeRuleTooShort, "r2", issue.CategoryRule, issue.SeverityLow),
			issue.New(issue.CodeRuleTooShort, "r3", issue.CategoryRule, issue.SeverityLow),
			issue.New(issue.CodeRuleTooShort, "r4", issue.CategoryRule, issue.SeverityLow),
			issue.New(issue.CodeRuleTooShort, "r5", issue.CategoryRule, issue.SeverityLow),
			issue.New(issue.CodeRuleTooShort, "r6", issue.CategoryRule, issue.SeverityLow),
			issue.New(issue.CodeRuleTooShort, "r7", issue.CategoryRule, issue.SeverityLow),
		},
	}
	result := Refine(issues, 3)
	if len(result) != 3 {
		t.Errorf("expected 3 issues (limited), got %d", len(result))
	}
}

func TestRefine_LimitZeroMeansNoLimit(t *testing.T) {
	rules := make([]issue.Issue, 7)
	for i := range rules {
		rules[i] = issue.New(issue.CodeRuleTooShort, "r", issue.CategoryRule, issue.SeverityLow)
	}
	issues := scoring.IssueSet{Rules: rules}
	result := Refine(issues, 0)
	if len(result) != 7 {
		t.Errorf("expected 7 issues (no limit), got %d", len(result))
	}
}

func TestRefine_DefaultLimit(t *testing.T) {
	mk := func(code, msg, cat string, sev int) issue.Issue { return issue.New(code, msg, cat, sev) }
	issues := scoring.IssueSet{
		Rules:      []issue.Issue{mk(issue.CodeRuleTooShort, "r1", issue.CategoryRule, issue.SeverityLow), mk(issue.CodeRuleTooShort, "r2", issue.CategoryRule, issue.SeverityLow), mk(issue.CodeRuleTooShort, "r3", issue.CategoryRule, issue.SeverityLow)},
		Patterns:   []issue.Issue{mk(issue.CodePatternKeyboard, "p1", issue.CategoryPattern, issue.SeverityMed), mk(issue.CodePatternKeyboard, "p2", issue.CategoryPattern, issue.SeverityMed), mk(issue.CodePatternKeyboard, "p3", issue.CategoryPattern, issue.SeverityMed)},
		Dictionary: []issue.Issue{mk(issue.CodeDictCommonPassword, "d1", issue.CategoryDictionary, issue.SeverityHigh), mk(issue.CodeDictCommonPassword, "d2", issue.CategoryDictionary, issue.SeverityHigh), mk(issue.CodeDictCommonPassword, "d3", issue.CategoryDictionary, issue.SeverityHigh)},
	}
	result := Refine(issues, DefaultMaxIssues)
	if len(result) > DefaultMaxIssues {
		t.Errorf("expected at most %d issues, got %d", DefaultMaxIssues, len(result))
	}
}

func TestRefine_DedupThenLimit(t *testing.T) {
	issues := scoring.IssueSet{
		Rules:      []issue.Issue{issue.New(issue.CodeRuleTooShort, "Some rule issue", issue.CategoryRule, issue.SeverityLow)},
		Patterns:   []issue.Issue{issue.New(issue.CodePatternSubstitution, "Contains common word with substitution: 'dragon'", issue.CategoryPattern, issue.SeverityMed)},
		Dictionary: []issue.Issue{issue.New(issue.CodeDictCommonWord, "Contains common word: 'dragon'", issue.CategoryDictionary, issue.SeverityHigh), issue.New(issue.CodeDictCommonPassword, "Another dict issue", issue.CategoryDictionary, issue.SeverityHigh)},
	}
	result := Refine(issues, 0)
	if len(result) != 3 {
		t.Errorf("expected 3 issues after dedup, got %d: %v", len(result), result)
	}
}

// ---------------------------------------------------------------------------
// dedup
// ---------------------------------------------------------------------------

func TestDedup_NoDuplicates(t *testing.T) {
	input := []rankedIssue{
		{issue.New(issue.CodeDictCommonPassword, "msg A", issue.CategoryDictionary, issue.SeverityHigh), 0},
		{issue.New(issue.CodePatternKeyboard, "msg B", issue.CategoryPattern, issue.SeverityMed), 1},
		{issue.New(issue.CodeRuleTooShort, "msg C", issue.CategoryRule, issue.SeverityLow), 2},
	}
	result := dedup(input)
	if len(result) != 3 {
		t.Errorf("expected 3, got %d", len(result))
	}
}

func TestDedup_SameToken(t *testing.T) {
	input := []rankedIssue{
		{issue.New(issue.CodeDictCommonWord, "Contains common word: 'pass'", issue.CategoryDictionary, issue.SeverityHigh), 0},
		{issue.New(issue.CodePatternSubstitution, "Contains common word with substitution: 'pass'", issue.CategoryPattern, issue.SeverityMed), 1},
	}
	result := dedup(input)
	if len(result) != 1 {
		t.Errorf("expected 1 after dedup, got %d: %v", len(result), result)
	}
	if result[0].issue.Severity != issue.SeverityHigh {
		t.Errorf("expected dict severity to win, got %d", result[0].issue.Severity)
	}
}

// ---------------------------------------------------------------------------
// sortBySeverity
// ---------------------------------------------------------------------------

func TestSortBySeverity(t *testing.T) {
	input := []rankedIssue{
		{issue.New(issue.CodeRuleTooShort, "rule", issue.CategoryRule, issue.SeverityLow), 0},
		{issue.New(issue.CodeDictCommonPassword, "dict", issue.CategoryDictionary, issue.SeverityHigh), 1},
		{issue.New(issue.CodePatternKeyboard, "pattern", issue.CategoryPattern, issue.SeverityMed), 2},
	}
	sortBySeverity(input)
	if input[0].issue.Severity != issue.SeverityHigh {
		t.Errorf("first should be dict, got severity %d", input[0].issue.Severity)
	}
	if input[1].issue.Severity != issue.SeverityMed {
		t.Errorf("second should be pattern, got severity %d", input[1].issue.Severity)
	}
	if input[2].issue.Severity != issue.SeverityLow {
		t.Errorf("third should be rule, got severity %d", input[2].issue.Severity)
	}
}

func TestSortBySeverity_StableTies(t *testing.T) {
	input := []rankedIssue{
		{issue.New(issue.CodeDictCommonPassword, "second dict", issue.CategoryDictionary, issue.SeverityHigh), 1},
		{issue.New(issue.CodeDictCommonPassword, "first dict", issue.CategoryDictionary, issue.SeverityHigh), 0},
	}
	sortBySeverity(input)
	if input[0].issue.Message != "first dict" {
		t.Errorf("expected stable sort, got %q first", input[0].issue.Message)
	}
}

// ---------------------------------------------------------------------------
// extractQuoted
// ---------------------------------------------------------------------------

func TestExtractQuoted(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Contains keyword: 'hello'", "hello"},
		{"No quotes here", ""},
		{"Only one 'quote", ""},
		{"Contains 'multi word token'", "multi word token"},
		{"Empty quotes ''", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := extractQuoted(tt.input); got != tt.expected {
				t.Errorf("extractQuoted(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GeneratePositive
// ---------------------------------------------------------------------------

func TestGeneratePositive_StrongPassword(t *testing.T) {
	// 20-char, 4 charsets, no issues, 120 bits.
	msgs := GeneratePositive("Xk9$mP2!vR7@nL4&wQzB", scoring.IssueSet{}, 120)
	assertContainsMsg(t, msgs, "Good length")
	assertContainsMsg(t, msgs, "character diversity")
	assertContainsMsg(t, msgs, "No common patterns")
	assertContainsMsg(t, msgs, "Not found in common password")
	assertContainsMsg(t, msgs, "Good entropy")
}

func TestGeneratePositive_Empty(t *testing.T) {
	msgs := GeneratePositive("", scoring.IssueSet{}, 0)
	if len(msgs) != 0 {
		t.Errorf("expected no positive feedback for empty password, got %v", msgs)
	}
}

func TestGeneratePositive_ShortPassword(t *testing.T) {
	msgs := GeneratePositive("abc", scoring.IssueSet{}, 14)
	// Should not get "Good length" or "Good entropy".
	for _, m := range msgs {
		if strings.Contains(m, "Good length") {
			t.Errorf("short password should not get length praise: %v", msgs)
		}
		if strings.Contains(m, "Good entropy") {
			t.Errorf("low-entropy password should not get entropy praise: %v", msgs)
		}
	}
}

func TestGeneratePositive_NoPatternPraise_WhenPatternsExist(t *testing.T) {
	issues := scoring.IssueSet{
		Patterns: []issue.Issue{issue.New(issue.CodePatternKeyboard, "keyboard pattern found", issue.CategoryPattern, issue.SeverityMed)},
	}
	msgs := GeneratePositive("qwertyuiop12345!", issues, 80)
	for _, m := range msgs {
		if strings.Contains(m, "No common patterns") {
			t.Errorf("should not praise patterns when patterns exist: %v", msgs)
		}
	}
}

func TestGeneratePositive_NoDictPraise_WhenDictIssuesExist(t *testing.T) {
	issues := scoring.IssueSet{
		Dictionary: []issue.Issue{issue.New(issue.CodeDictCommonPassword, "common password", issue.CategoryDictionary, issue.SeverityHigh)},
	}
	msgs := GeneratePositive("password12345678", issues, 80)
	for _, m := range msgs {
		if strings.Contains(m, "Not found") {
			t.Errorf("should not praise dict when dict issues exist: %v", msgs)
		}
	}
}

func TestGeneratePositive_OnlyDeservedPraise(t *testing.T) {
	issues := scoring.IssueSet{
		Patterns: []issue.Issue{issue.New(issue.CodePatternSequence, "sequence found", issue.CategoryPattern, issue.SeverityMed)},
	}
	msgs := GeneratePositive("abcdefABCDEFGH", issues, 50)
	// Should NOT get: length (<16), entropy (<60), pattern-free.
	// Should get: "No common patterns" is false (patterns exist), dict-free.
	for _, m := range msgs {
		if strings.Contains(m, "Good length") {
			t.Error("14 chars < 16 threshold")
		}
		if strings.Contains(m, "Good entropy") {
			t.Error("50 bits < 60 threshold")
		}
		if strings.Contains(m, "No common patterns") {
			t.Error("pattern issues exist")
		}
	}
	assertContainsMsg(t, msgs, "Not found in common password")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func assertContains(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(strings.ToLower(s), strings.ToLower(substr)) {
		t.Errorf("expected %q to contain %q", s, substr)
	}
}

func assertContainsMsg(t *testing.T, msgs []string, substr string) {
	t.Helper()
	for _, m := range msgs {
		if strings.Contains(strings.ToLower(m), strings.ToLower(substr)) {
			return
		}
	}
	t.Errorf("expected a message containing %q in %v", substr, msgs)
}
