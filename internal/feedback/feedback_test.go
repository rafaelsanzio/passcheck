package feedback

import (
	"strings"
	"testing"

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
		Rules:      []string{"Add at least one uppercase letter"},
		Patterns:   []string{"Contains sequence: 'abcd'"},
		Dictionary: []string{"This password appears in common password lists"},
	}
	result := Refine(issues, 0)
	// Dictionary (severity 3) should come first, then patterns (2), then rules (1).
	if len(result) < 3 {
		t.Fatalf("expected 3 issues, got %d", len(result))
	}
	assertContains(t, result[0], "password lists")
	assertContains(t, result[1], "sequence")
	assertContains(t, result[2], "uppercase")
}

func TestRefine_Dedup(t *testing.T) {
	// Same quoted word 'sunshine' from two different phases.
	issues := scoring.IssueSet{
		Patterns:   []string{"Contains common word with substitution: 'sunshine'"},
		Dictionary: []string{"Contains common word: 'sunshine'"},
	}
	result := Refine(issues, 0)
	// Only the dictionary version (higher severity) should survive.
	if len(result) != 1 {
		t.Errorf("expected 1 issue after dedup, got %d: %v", len(result), result)
	}
	if len(result) > 0 {
		assertContains(t, result[0], "common word: 'sunshine'")
	}
}

func TestRefine_DedupKeepsHighestSeverity(t *testing.T) {
	issues := scoring.IssueSet{
		Rules:      []string{"Avoid repeating character 'aaa'"},
		Patterns:   []string{"Contains repeated block: 'aaa'"},
		Dictionary: []string{"Contains common word: 'aaa'"},
	}
	result := Refine(issues, 0)
	// All three reference 'aaa'. Dictionary (severity 3) wins.
	if len(result) != 1 {
		t.Errorf("expected 1 issue, got %d: %v", len(result), result)
	}
	if len(result) > 0 {
		assertContains(t, result[0], "common word")
	}
}

func TestRefine_UnquotedMessagesNeverDeduped(t *testing.T) {
	issues := scoring.IssueSet{
		Dictionary: []string{
			"This password appears in common password lists",
			"This is a leetspeak variant of a common password",
		},
	}
	result := Refine(issues, 0)
	if len(result) != 2 {
		t.Errorf("expected 2 issues (unquoted), got %d: %v", len(result), result)
	}
}

func TestRefine_Limit(t *testing.T) {
	issues := scoring.IssueSet{
		Rules: []string{"r1", "r2", "r3", "r4", "r5", "r6", "r7"},
	}
	result := Refine(issues, 3)
	if len(result) != 3 {
		t.Errorf("expected 3 issues (limited), got %d", len(result))
	}
}

func TestRefine_LimitZeroMeansNoLimit(t *testing.T) {
	issues := scoring.IssueSet{
		Rules: []string{"r1", "r2", "r3", "r4", "r5", "r6", "r7"},
	}
	result := Refine(issues, 0)
	if len(result) != 7 {
		t.Errorf("expected 7 issues (no limit), got %d", len(result))
	}
}

func TestRefine_DefaultLimit(t *testing.T) {
	issues := scoring.IssueSet{
		Rules:      []string{"r1", "r2", "r3"},
		Patterns:   []string{"p1", "p2", "p3"},
		Dictionary: []string{"d1", "d2", "d3"},
	}
	result := Refine(issues, DefaultMaxIssues)
	if len(result) > DefaultMaxIssues {
		t.Errorf("expected at most %d issues, got %d", DefaultMaxIssues, len(result))
	}
}

func TestRefine_DedupThenLimit(t *testing.T) {
	// 3 messages about 'dragon' from different phases + 2 unique.
	issues := scoring.IssueSet{
		Rules:      []string{"Some rule issue"},
		Patterns:   []string{"Contains common word with substitution: 'dragon'"},
		Dictionary: []string{"Contains common word: 'dragon'", "Another dict issue"},
	}
	// After dedup: 3 unique messages (rule, deduped dragon, another dict).
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
		{"msg A", severityDict, 0},
		{"msg B", severityPattern, 1},
		{"msg C", severityRule, 2},
	}
	result := dedup(input)
	if len(result) != 3 {
		t.Errorf("expected 3, got %d", len(result))
	}
}

func TestDedup_SameToken(t *testing.T) {
	input := []rankedIssue{
		{"Contains common word: 'pass'", severityDict, 0},
		{"Contains common word with substitution: 'pass'", severityPattern, 1},
	}
	result := dedup(input)
	if len(result) != 1 {
		t.Errorf("expected 1 after dedup, got %d: %v", len(result), result)
	}
	if result[0].severity != severityDict {
		t.Errorf("expected dict severity to win, got %d", result[0].severity)
	}
}

// ---------------------------------------------------------------------------
// sortBySeverity
// ---------------------------------------------------------------------------

func TestSortBySeverity(t *testing.T) {
	input := []rankedIssue{
		{"rule", severityRule, 0},
		{"dict", severityDict, 1},
		{"pattern", severityPattern, 2},
	}
	sortBySeverity(input)
	if input[0].severity != severityDict {
		t.Errorf("first should be dict, got severity %d", input[0].severity)
	}
	if input[1].severity != severityPattern {
		t.Errorf("second should be pattern, got severity %d", input[1].severity)
	}
	if input[2].severity != severityRule {
		t.Errorf("third should be rule, got severity %d", input[2].severity)
	}
}

func TestSortBySeverity_StableTies(t *testing.T) {
	input := []rankedIssue{
		{"second dict", severityDict, 1},
		{"first dict", severityDict, 0},
	}
	sortBySeverity(input)
	// Same severity → lower index first.
	if input[0].message != "first dict" {
		t.Errorf("expected stable sort, got %q first", input[0].message)
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
		Patterns: []string{"keyboard pattern found"},
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
		Dictionary: []string{"common password"},
	}
	msgs := GeneratePositive("password12345678", issues, 80)
	for _, m := range msgs {
		if strings.Contains(m, "Not found") {
			t.Errorf("should not praise dict when dict issues exist: %v", msgs)
		}
	}
}

func TestGeneratePositive_OnlyDeservedPraise(t *testing.T) {
	// 14-char, 2 charsets, some pattern issues, 50 bits.
	issues := scoring.IssueSet{
		Patterns: []string{"sequence found"},
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
