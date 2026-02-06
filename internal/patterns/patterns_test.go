package patterns

import (
	"strings"
	"testing"

	"github.com/rafaelsanzio/passcheck/internal/leet"
)

// ---------------------------------------------------------------------------
// Check (integration)
// ---------------------------------------------------------------------------

func TestCheck_NoPatterns(t *testing.T) {
	issues := Check("Xk9$mP2!vR7@nL4&")
	if len(issues) != 0 {
		t.Errorf("expected no pattern issues, got %v", issues)
	}
}

func TestCheck_KeyboardAndSequence(t *testing.T) {
	// "qwerty1234" has a keyboard pattern and a numeric sequence.
	issues := Check("qwerty1234")
	assertContainsIssue(t, issues, "keyboard")
	assertContainsIssue(t, issues, "sequence")
}

func TestCheck_CaseInsensitive(t *testing.T) {
	// Patterns should be detected regardless of case.
	issues := Check("QWERTY")
	assertContainsIssue(t, issues, "keyboard")
}

func TestCheck_EmptyPassword(t *testing.T) {
	issues := Check("")
	if len(issues) != 0 {
		t.Errorf("expected no issues for empty password, got %v", issues)
	}
}

// ---------------------------------------------------------------------------
// Keyboard Patterns
// ---------------------------------------------------------------------------

func TestCheckKeyboard(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		wantIssue bool
		contains  string // substring expected in issue message
	}{
		// Horizontal rows
		{"qwerty forward", "qwerty", true, "qwerty"},
		{"asdf forward", "asdfg", true, "asdfg"},
		{"zxcvbn forward", "zxcvbn", true, "zxcvbn"},
		{"number row", "12345", true, "1234"},

		// Reversed rows
		{"qwerty reversed", "ytrewq", true, "ytrewq"},
		{"number row reversed", "09876", true, "0987"},

		// Vertical columns (only those >= 4 chars form patterns via diag/row combos)
		// "qaz" is only 3 chars, below the threshold of 4
		{"vertical qaz (too short)", "qaz", false, ""},

		// Diagonals
		{"diagonal qwsz", "qwsz", true, "qwsz"},
		{"diagonal rtgv", "rtgv", true, "rtgv"},

		// Below threshold
		{"3 chars from row", "qwe", false, ""},
		{"random chars", "xmzp", false, ""},

		// Embedded in longer password
		{"embedded qwerty", "xxxqwertyxxx", true, "qwerty"},

		// Short password
		{"short password", "ab", false, ""},
		{"empty", "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := checkKeyboard(strings.ToLower(tt.password), DefaultOptions())
			hasIssue := len(issues) > 0
			if hasIssue != tt.wantIssue {
				t.Errorf("checkKeyboard(%q): got issue=%v, want issue=%v (issues: %v)",
					tt.password, hasIssue, tt.wantIssue, issues)
			}
			if tt.contains != "" {
				assertContainsIssue(t, issues, tt.contains)
			}
		})
	}
}

func TestCheckKeyboard_NoDuplicates(t *testing.T) {
	// A password with overlapping keyboard patterns should not report
	// the same match twice.
	issues := checkKeyboard("qwertyuiop", DefaultOptions())
	seen := make(map[string]bool)
	for _, issue := range issues {
		if seen[issue] {
			t.Errorf("duplicate issue: %s", issue)
		}
		seen[issue] = true
	}
}

// ---------------------------------------------------------------------------
// Sequence Detection
// ---------------------------------------------------------------------------

func TestCheckSequence(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		wantIssue bool
		contains  string
	}{
		// Ascending step +1
		{"abcd ascending", "abcdef", true, "abcdef"},
		{"1234 ascending", "1234", true, "1234"},
		{"mnop ascending", "mnopqr", true, "mnopqr"},

		// Descending step -1
		{"dcba descending", "dcba", true, "dcba"},
		{"9876 descending", "9876", true, "9876"},
		{"zyxw descending", "zyxwvu", true, "zyxwvu"},

		// Step +2
		{"2468 step +2", "2468", true, "2468"},
		{"aceg step +2", "aceg", true, "aceg"},

		// Step -2
		{"8642 step -2", "8642", true, "8642"},
		{"geca step -2", "geca", true, "geca"},

		// Below threshold
		{"abc only 3", "abc", false, ""},
		{"12 only 2", "12", false, ""},

		// Embedded in longer password
		{"embedded 1234", "xxx1234xxx", true, "1234"},

		// No sequence
		{"random", "xmzp", false, ""},
		{"empty", "", false, ""},

		// Mixed (non-sequential)
		{"alternating", "ababab", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := checkSequence(strings.ToLower(tt.password), DefaultOptions())
			hasIssue := len(issues) > 0
			if hasIssue != tt.wantIssue {
				t.Errorf("checkSequence(%q): got issue=%v, want issue=%v (issues: %v)",
					tt.password, hasIssue, tt.wantIssue, issues)
			}
			if tt.contains != "" {
				assertContainsIssue(t, issues, tt.contains)
			}
		})
	}
}

func TestCheckSequence_MultipleRuns(t *testing.T) {
	// "abcd9876" contains an ascending and a descending run.
	issues := checkSequence("abcd9876", DefaultOptions())
	if len(issues) < 2 {
		t.Errorf("expected at least 2 sequence issues, got %d: %v", len(issues), issues)
	}
}

func TestFindArithmeticRuns(t *testing.T) {
	tests := []struct {
		name    string
		runes   []rune
		step    int
		minLen  int
		wantLen int
	}{
		{"ascending 4", []rune("abcdef"), 1, 4, 1},
		{"descending 4", []rune("fedcba"), -1, 4, 1},
		{"no run", []rune("xmzp"), 1, 4, 0},
		{"two runs", []rune("abcdxyzwvut"), 1, 4, 1},
		{"short run", []rune("abc"), 1, 4, 0},
		{"empty", []rune(""), 1, 4, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runs := findArithmeticRuns(tt.runes, tt.step, tt.minLen)
			if len(runs) != tt.wantLen {
				t.Errorf("expected %d runs, got %d: %v", tt.wantLen, len(runs), runs)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Repeated Blocks
// ---------------------------------------------------------------------------

func TestCheckRepeatedBlocks(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		wantIssue bool
		contains  string
	}{
		// Basic repeated blocks
		{"abcabc", "abcabc", true, "abc"},
		{"1212", "1212", true, "12"},
		{"passpass", "passpass", true, "pass"},
		{"121212 triple", "121212", true, "12"},

		// Single-char blocks are skipped (handled by rules)
		{"aaaa not flagged", "aaaa", false, ""},
		{"aaaaaa not flagged", "aaaaaa", false, ""},

		// Below threshold
		{"too short", "ab", false, ""},
		{"empty", "", false, ""},

		// Embedded
		{"embedded abcabc", "xxxabcabcxxx", true, "abc"},

		// No repetition
		{"no repeat", "abcdef", false, ""},

		// Unicode blocks
		{"unicode block", "héhé", true, "hé"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := checkRepeatedBlocks(strings.ToLower(tt.password))
			hasIssue := len(issues) > 0
			if hasIssue != tt.wantIssue {
				t.Errorf("checkRepeatedBlocks(%q): got issue=%v, want issue=%v (issues: %v)",
					tt.password, hasIssue, tt.wantIssue, issues)
			}
			if tt.contains != "" {
				assertContainsIssue(t, issues, tt.contains)
			}
		})
	}
}

func TestCheckRepeatedBlocks_NoDuplicates(t *testing.T) {
	// "abcabcabc" should report "abc" only once.
	issues := checkRepeatedBlocks("abcabcabc")
	count := 0
	for _, issue := range issues {
		if strings.Contains(issue, "'abc'") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 'abc' reported once, got %d times in: %v", count, issues)
	}
}

func TestAllSameRune(t *testing.T) {
	tests := []struct {
		name   string
		runes  []rune
		expect bool
	}{
		{"empty", []rune{}, true},
		{"single", []rune{'a'}, true},
		{"same", []rune{'a', 'a', 'a'}, true},
		{"different", []rune{'a', 'b', 'a'}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allSameRune(tt.runes); got != tt.expect {
				t.Errorf("allSameRune(%v) = %v, want %v", tt.runes, got, tt.expect)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Substitution Detection
// ---------------------------------------------------------------------------

func TestCheckSubstitution(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		wantIssue bool
		contains  string
	}{
		// Classic leetspeak
		{"p@ssw0rd", "p@ssw0rd", true, "password"},
		{"p@$$w0rd", "p@$$w0rd", true, "passw"},
		{"@dm1n", "@dm1n", true, "admin"},
		{"h3ll0", "h3ll0", true, "hello"},
		{"l3tm31n", "l3tm31n", true, "letmein"},
		{"$unsh1n3", "$unsh1n3", true, "sunshine"},

		// No substitution made (all normal letters)
		{"password plain", "password", false, ""},
		{"admin plain", "admin", false, ""},

		// No match after normalization
		{"random leet", "x@z0q", false, ""},

		// Embedded in longer password
		{"embedded p@ss", "xxxp@$$w0rdxxx", true, "passw"},

		// Empty
		{"empty", "", false, ""},

		// No leet chars
		{"no leet", "abcdef", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := checkSubstitution(strings.ToLower(tt.password))
			hasIssue := len(issues) > 0
			if hasIssue != tt.wantIssue {
				t.Errorf("checkSubstitution(%q): got issue=%v, want issue=%v (issues: %v)",
					tt.password, hasIssue, tt.wantIssue, issues)
			}
			if tt.contains != "" {
				assertContainsIssue(t, issues, tt.contains)
			}
		})
	}
}

func TestNormalizeLeet(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"@ to a", "p@ss", "pass"},
		{"0 to o", "h0me", "home"},
		{"1 to i", "adm1n", "admin"},
		{"3 to e", "h3llo", "hello"},
		{"$ to s", "$ecret", "secret"},
		{"5 to s", "5ecret", "secret"},
		{"7 to t", "7rust", "trust"},
		{"4 to a", "4dmin", "admin"},
		{"8 to b", "8all", "ball"},
		{"! to i", "adm!n", "admin"},
		{"| to l", "|ove", "love"},
		{"+ to t", "+rust", "trust"},
		{"multiple subs", "p@$$w0rd", "password"},
		{"no subs needed", "hello", "hello"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := leet.Normalize(tt.input)
			if result != tt.expected {
				t.Errorf("leet.Normalize(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers (reverseStr)
// ---------------------------------------------------------------------------

func TestReverseStr(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"abc", "cba"},
		{"", ""},
		{"a", "a"},
		{"ab", "ba"},
		{"hello", "olleh"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := reverseStr(tt.input); got != tt.expected {
				t.Errorf("reverseStr(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Edge Cases
// ---------------------------------------------------------------------------

func TestCheck_VeryLongPassword(t *testing.T) {
	// A long random-looking password should have no pattern issues.
	password := "Xk9$mP2!vR7@nL4&wQ8zBj6#cF0^dH"
	issues := Check(password)
	if len(issues) != 0 {
		t.Errorf("expected no pattern issues for random password, got %v", issues)
	}
}

func TestCheck_AllKeyboardRow(t *testing.T) {
	issues := Check("qwertyuiop")
	assertContainsIssue(t, issues, "keyboard")
}

func TestCheck_FullAlphabet(t *testing.T) {
	issues := Check("abcdefghijklmnopqrstuvwxyz")
	assertContainsIssue(t, issues, "sequence")
}

func TestCheck_RepeatedBlockWithLeet(t *testing.T) {
	// "p@$$w0rdp@$$w0rd" — both repeated block and substitution.
	issues := Check("p@$$w0rdp@$$w0rd")
	assertContainsIssue(t, issues, "repeated block")
	assertContainsIssue(t, issues, "substitution")
}

// ---------------------------------------------------------------------------
// CheckWith — custom options
// ---------------------------------------------------------------------------

func TestCheckWith_StricterKeyboard(t *testing.T) {
	opts := DefaultOptions()
	opts.KeyboardMinLen = 3

	// "asd" (3 chars) is below default threshold but triggers with min=3.
	issues := CheckWith("asd", opts)
	assertContainsIssue(t, issues, "keyboard")

	// Not detected with defaults (min=4).
	issuesDef := Check("asd")
	if containsIssue(issuesDef, "keyboard") {
		t.Error("'asd' should not trigger keyboard detection with default min=4")
	}
}

func TestCheckWith_RelaxedSequence(t *testing.T) {
	opts := DefaultOptions()
	opts.SequenceMinLen = 6

	// "abcde" (5 chars) triggers with default min=4 but not with min=6.
	issues := CheckWith("abcde", opts)
	if containsIssue(issues, "sequence") {
		t.Error("'abcde' should not trigger with SequenceMinLen=6")
	}

	// Triggers with defaults.
	issuesDef := Check("abcde")
	assertContainsIssue(t, issuesDef, "sequence")
}

func TestCheckWith_EquivalentToCheck(t *testing.T) {
	pw := "qwerty1234"
	got := CheckWith(pw, DefaultOptions())
	want := Check(pw)

	if len(got) != len(want) {
		t.Errorf("CheckWith(default) and Check should match: got %d issues, want %d", len(got), len(want))
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func containsIssue(issues []string, substr string) bool {
	lower := strings.ToLower(substr)
	for _, issue := range issues {
		if strings.Contains(strings.ToLower(issue), lower) {
			return true
		}
	}
	return false
}

func assertContainsIssue(t *testing.T, issues []string, substr string) {
	t.Helper()
	if !containsIssue(issues, substr) {
		t.Errorf("expected an issue containing %q, got: %v", substr, issues)
	}
}
