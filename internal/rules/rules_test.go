package rules

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Check (integration)
// ---------------------------------------------------------------------------

func TestCheck_EmptyPassword(t *testing.T) {
	issues := Check("")
	// Empty password should at least flag length.
	assertContainsIssue(t, issues, "too short")
}

func TestCheck_StrongPassword(t *testing.T) {
	// A strong password that satisfies all rules should return no issues.
	issues := Check("Xk9$mP2!vR7@nL4&")
	if len(issues) != 0 {
		t.Errorf("expected no issues for strong password, got %v", issues)
	}
}

func TestCheck_MultipleViolations(t *testing.T) {
	// "aaa" is short, no upper, no digit, no symbol, and has repeated chars.
	issues := Check("aaa")
	if len(issues) < 3 {
		t.Errorf("expected multiple issues, got %d: %v", len(issues), issues)
	}
	assertContainsIssue(t, issues, "too short")
	assertContainsIssue(t, issues, "uppercase")
	assertContainsIssue(t, issues, "digit")
	assertContainsIssue(t, issues, "symbol")
	assertContainsIssue(t, issues, "repeating")
}

// ---------------------------------------------------------------------------
// Minimum Length
// ---------------------------------------------------------------------------

func TestCheckMinLength(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		wantIssue bool
	}{
		{"empty", "", true},
		{"1 char", "a", true},
		{"11 chars", "abcdefghijk", true},
		{"exactly 12 chars", "abcdefghijkl", false},
		{"13 chars", "abcdefghijklm", false},
		{"unicode chars counted correctly", "héllo wörld!", false}, // 12 runes
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := checkMinLength(tt.password, DefaultOptions())
			hasIssue := len(issues) > 0
			if hasIssue != tt.wantIssue {
				t.Errorf("checkMinLength(%q): got issue=%v, want issue=%v (issues: %v)",
					tt.password, hasIssue, tt.wantIssue, issues)
			}
			if hasIssue {
				assertContainsIssue(t, issues, "too short")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Character Set Analysis
// ---------------------------------------------------------------------------

func TestAnalyzeCharsets(t *testing.T) {
	tests := []struct {
		name       string
		password   string
		wantUpper  bool
		wantLower  bool
		wantDigit  bool
		wantSymbol bool
	}{
		{"empty", "", false, false, false, false},
		{"lowercase only", "abcdef", false, true, false, false},
		{"uppercase only", "ABCDEF", true, false, false, false},
		{"digits only", "123456", false, false, true, false},
		{"symbols only", "!@#$%^", false, false, false, true},
		{"lower + upper", "abcABC", true, true, false, false},
		{"all sets", "aA1!", true, true, true, true},
		{"unicode upper", "Ñ", true, false, false, false},
		{"unicode lower", "ñ", false, true, false, false},
		{"unicode digit", "٣", false, false, true, false}, // Arabic digit
		{"unicode symbol", "★", false, false, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := analyzeCharsets(tt.password)
			if cs.hasUpper != tt.wantUpper {
				t.Errorf("hasUpper: got %v, want %v", cs.hasUpper, tt.wantUpper)
			}
			if cs.hasLower != tt.wantLower {
				t.Errorf("hasLower: got %v, want %v", cs.hasLower, tt.wantLower)
			}
			if cs.hasDigit != tt.wantDigit {
				t.Errorf("hasDigit: got %v, want %v", cs.hasDigit, tt.wantDigit)
			}
			if cs.hasSymbol != tt.wantSymbol {
				t.Errorf("hasSymbol: got %v, want %v", cs.hasSymbol, tt.wantSymbol)
			}
		})
	}
}

func TestCheckCharsets(t *testing.T) {
	tests := []struct {
		name          string
		password      string
		wantIssues    int
		shouldContain []string // substrings to look for in issues
	}{
		{
			name:       "empty returns no charset issues",
			password:   "",
			wantIssues: 0,
		},
		{
			name:          "lowercase only missing 3 sets",
			password:      "abcdef",
			wantIssues:    3,
			shouldContain: []string{"uppercase", "digit", "symbol"},
		},
		{
			name:          "uppercase only missing 3 sets",
			password:      "ABCDEF",
			wantIssues:    3,
			shouldContain: []string{"lowercase", "digit", "symbol"},
		},
		{
			name:          "digits only missing 3 sets",
			password:      "123456",
			wantIssues:    3,
			shouldContain: []string{"uppercase", "lowercase", "symbol"},
		},
		{
			name:       "all character sets present",
			password:   "aA1!",
			wantIssues: 0,
		},
		{
			name:          "missing only symbol",
			password:      "aA1",
			wantIssues:    1,
			shouldContain: []string{"symbol"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := checkCharsets(tt.password, DefaultOptions())
			if len(issues) != tt.wantIssues {
				t.Errorf("got %d issues, want %d: %v", len(issues), tt.wantIssues, issues)
			}
			for _, substr := range tt.shouldContain {
				assertContainsIssue(t, issues, substr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Whitespace / Control Characters
// ---------------------------------------------------------------------------

func TestCheckWhitespace(t *testing.T) {
	tests := []struct {
		name           string
		password       string
		wantWhitespace bool
		wantControl    bool
	}{
		{"no whitespace", "abcdef", false, false},
		{"space", "abc def", true, false},
		{"tab", "abc\tdef", true, false},
		{"newline", "abc\ndef", true, false},
		{"carriage return", "abc\rdef", true, false},
		{"control char NUL", "abc\x00def", false, true},
		{"control char BEL", "abc\x07def", false, true},
		{"control char ESC", "abc\x1bdef", false, true},
		{"both whitespace and control", "abc \x00def", true, true},
		{"unicode space (NBSP)", "abc\u00a0def", true, false},
		{"empty string", "", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := checkWhitespace(tt.password)

			hasWhitespace := containsIssue(issues, "whitespace")
			hasControl := containsIssue(issues, "control")

			if hasWhitespace != tt.wantWhitespace {
				t.Errorf("whitespace: got %v, want %v (issues: %v)", hasWhitespace, tt.wantWhitespace, issues)
			}
			if hasControl != tt.wantControl {
				t.Errorf("control: got %v, want %v (issues: %v)", hasControl, tt.wantControl, issues)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Repeated Characters
// ---------------------------------------------------------------------------

func TestCheckRepeatedChars(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		wantIssue bool
	}{
		{"no repeats", "abcdef", false},
		{"2 consecutive (below threshold)", "aabcdef", false},
		{"exactly 3 consecutive", "aaabcdef", true},
		{"4 consecutive", "aaaabcdef", true},
		{"multiple different repeats", "aaabbb", true},
		{"repeated digits", "111abc", true},
		{"repeated symbols", "!!!abc", true},
		{"short password no repeat", "ab", false},
		{"short password with repeat", "aaa", true},
		{"empty", "", false},
		{"alternating chars", "ababab", false},
		{"repeat in middle", "abcccdef", true},
		{"repeat at end", "abcddd", true},
		{"unicode repeated", "äääbc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := checkRepeatedChars(tt.password, DefaultOptions())
			hasIssue := len(issues) > 0
			if hasIssue != tt.wantIssue {
				t.Errorf("checkRepeatedChars(%q): got issue=%v, want issue=%v (issues: %v)",
					tt.password, hasIssue, tt.wantIssue, issues)
			}
			if hasIssue {
				assertContainsIssue(t, issues, "repeating")
			}
		})
	}
}

func TestCheckRepeatedChars_MultipleGroups(t *testing.T) {
	// "aaabbb" should report two separate issues (one for 'a', one for 'b').
	issues := checkRepeatedChars("aaabbb", DefaultOptions())
	if len(issues) != 2 {
		t.Errorf("expected 2 issues for 'aaabbb', got %d: %v", len(issues), issues)
	}
}

func TestCheckRepeatedChars_NoDuplicateIssues(t *testing.T) {
	// "aaaa" is a single group of 'a' — should produce only one issue.
	issues := checkRepeatedChars("aaaa", DefaultOptions())
	if len(issues) != 1 {
		t.Errorf("expected 1 issue for 'aaaa', got %d: %v", len(issues), issues)
	}
}

// ---------------------------------------------------------------------------
// Edge Cases
// ---------------------------------------------------------------------------

func TestCheck_VeryLongPassword(t *testing.T) {
	// 200-char password with all character sets, no repeats.
	password := strings.Repeat("aB1!", 50)
	issues := Check(password)
	// Should have no issues (length ok, all charsets, no whitespace, no repeats).
	if len(issues) != 0 {
		t.Errorf("expected no issues for long varied password, got %v", issues)
	}
}

func TestCheck_UnicodePassword(t *testing.T) {
	// Unicode password with 12+ runes, mixed case, digit, symbol.
	password := "Héllo1Wörld!"
	issues := Check(password)
	if len(issues) != 0 {
		t.Errorf("expected no issues for unicode password %q, got %v", password, issues)
	}
}

func TestCheck_OnlySpaces(t *testing.T) {
	password := "            " // 12 spaces
	issues := Check(password)
	assertContainsIssue(t, issues, "whitespace")
}

func TestCheck_AllSameChar(t *testing.T) {
	password := "aaaaaaaaaaaa" // 12 'a's
	issues := Check(password)
	assertContainsIssue(t, issues, "repeating")
	assertContainsIssue(t, issues, "uppercase")
	assertContainsIssue(t, issues, "digit")
	assertContainsIssue(t, issues, "symbol")
}

// ---------------------------------------------------------------------------
// CheckWith — custom options
// ---------------------------------------------------------------------------

func TestCheckWith_CustomMinLength(t *testing.T) {
	opts := DefaultOptions()
	opts.MinLength = 6

	// "abcdefgh" (8 chars) passes with min 6, fails with default 12.
	issues := CheckWith("abcdefgh", opts)
	for _, issue := range issues {
		if containsIssue([]string{issue}, "too short") {
			t.Error("8-char password should pass with MinLength=6")
		}
	}

	// Still fails with default.
	issuesDef := Check("abcdefgh")
	assertContainsIssue(t, issuesDef, "too short")
}

func TestCheckWith_DisableUpperRequirement(t *testing.T) {
	opts := DefaultOptions()
	opts.RequireUpper = false

	// "abcdefghijkl" (12 lowercase chars) — no uppercase issue.
	issues := CheckWith("abcdefghijkl", opts)
	if containsIssue(issues, "uppercase") {
		t.Error("should not require uppercase when RequireUpper=false")
	}
	// Still requires digit and symbol.
	assertContainsIssue(t, issues, "digit")
	assertContainsIssue(t, issues, "symbol")
}

func TestCheckWith_DisableAllCharsets(t *testing.T) {
	opts := DefaultOptions()
	opts.RequireUpper = false
	opts.RequireLower = false
	opts.RequireDigit = false
	opts.RequireSymbol = false

	issues := CheckWith("abcdefghijkl", opts)
	// No charset issues — only whitespace/repeat checks remain.
	for _, issue := range issues {
		if containsIssue([]string{issue}, "uppercase") ||
			containsIssue([]string{issue}, "lowercase") ||
			containsIssue([]string{issue}, "digit") ||
			containsIssue([]string{issue}, "symbol") {
			t.Errorf("no charset issues expected, got: %v", issues)
		}
	}
}

func TestCheckWith_CustomMaxRepeats(t *testing.T) {
	opts := DefaultOptions()
	opts.MaxRepeats = 5

	// "aaaa" (4 repeats) passes with MaxRepeats=5.
	issues := CheckWith("aaaaB1!xyzab", opts)
	if containsIssue(issues, "repeating") {
		t.Error("4 repeats should pass with MaxRepeats=5")
	}

	// "aaaaa" (5 repeats) fails with MaxRepeats=5.
	issues2 := CheckWith("aaaaaB1!xyza", opts)
	assertContainsIssue(t, issues2, "repeating")
}

func TestCheckWith_EquivalentToCheck(t *testing.T) {
	pw := "Xk9$mP2!vR7@nL4&"
	got := CheckWith(pw, DefaultOptions())
	want := Check(pw)

	if len(got) != len(want) {
		t.Errorf("CheckWith(default) and Check should match: got %v, want %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// containsIssue checks if any issue message contains the given substring.
func containsIssue(issues []string, substr string) bool {
	lower := strings.ToLower(substr)
	for _, issue := range issues {
		if strings.Contains(strings.ToLower(issue), lower) {
			return true
		}
	}
	return false
}

// assertContainsIssue fails the test if no issue contains the expected substring.
func assertContainsIssue(t *testing.T, issues []string, substr string) {
	t.Helper()
	if !containsIssue(issues, substr) {
		t.Errorf("expected an issue containing %q, got: %v", substr, issues)
	}
}
