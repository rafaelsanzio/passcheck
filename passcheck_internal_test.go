package passcheck

import (
	"strings"
	"testing"

	"github.com/rafaelsanzio/passcheck/internal/issue"
	"github.com/rafaelsanzio/passcheck/internal/scoring"
)

func TestConstantSynchronization(t *testing.T) {
	tests := []struct {
		name    string
		public  string
		internal string
	}{
		{"CodeRuleTooShort", CodeRuleTooShort, issue.CodeRuleTooShort},
		{"CodeRuleNoUpper", CodeRuleNoUpper, issue.CodeRuleNoUpper},
		{"CodeRuleNoLower", CodeRuleNoLower, issue.CodeRuleNoLower},
		{"CodeRuleNoDigit", CodeRuleNoDigit, issue.CodeRuleNoDigit},
		{"CodeRuleNoSymbol", CodeRuleNoSymbol, issue.CodeRuleNoSymbol},
		{"CodeRuleWhitespace", CodeRuleWhitespace, issue.CodeRuleWhitespace},
		{"CodeRuleControlChar", CodeRuleControlChar, issue.CodeRuleControlChar},
		{"CodeRuleRepeatedChars", CodeRuleRepeatedChars, issue.CodeRuleRepeatedChars},
		{"CodePatternKeyboard", CodePatternKeyboard, issue.CodePatternKeyboard},
		{"CodePatternSequence", CodePatternSequence, issue.CodePatternSequence},
		{"CodePatternBlock", CodePatternBlock, issue.CodePatternBlock},
		{"CodePatternDate", CodePatternDate, issue.CodePatternDate},
		{"CodePatternSubstitution", CodePatternSubstitution, issue.CodePatternSubstitution},
		{"CodeDictCommonPassword", CodeDictCommonPassword, issue.CodeDictCommonPassword},
		{"CodeDictLeetVariant", CodeDictLeetVariant, issue.CodeDictLeetVariant},
		{"CodeDictCommonWord", CodeDictCommonWord, issue.CodeDictCommonWord},
		{"CodeDictCommonWordSub", CodeDictCommonWordSub, issue.CodeDictCommonWordSub},
		{"CodeHIBPBreached", CodeHIBPBreached, issue.CodeHIBPBreached},
		{"CodeContextWord", CodeContextWord, issue.CodeContextWord},
		{"VerdictVeryWeak", VerdictVeryWeak, scoring.Verdict(0)},
		{"VerdictWeak", VerdictWeak, scoring.Verdict(scoring.ThresholdWeak)},
		{"VerdictOkay", VerdictOkay, scoring.Verdict(scoring.ThresholdOkay)},
		{"VerdictStrong", VerdictStrong, scoring.Verdict(scoring.ThresholdStrong)},
		{"VerdictVeryStrong", VerdictVeryStrong, scoring.Verdict(100)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.public != tt.internal {
				t.Errorf("constant drift detected: public %q (%s) != internal %s", tt.name, tt.public, tt.internal)
			}
		})
	}
}

func TestToPublicIssues(t *testing.T) {
	internal := []issue.Issue{
		{
			Code:     "TEST_CODE",
			Message:  "Test message",
			Category: "test_cat",
			Severity: 3,
		},
	}

	t.Run("redact_false", func(t *testing.T) {
		public := toPublicIssues(internal, false)
		if len(public) != 1 {
			t.Fatalf("expected 1 issue, got %d", len(public))
		}
		iss := public[0]
		if iss.Code != internal[0].Code ||
			iss.Message != internal[0].Message ||
			iss.Category != internal[0].Category ||
			iss.Severity != internal[0].Severity {
			t.Errorf("conversion mismatch: got %+v, want %+v", iss, internal[0])
		}
	})

	t.Run("redact_true", func(t *testing.T) {
		sensitive := []issue.Issue{
			{
				Code:     "DICT_COMMON_PASSWORD",
				Message:  "Password matches common password: 'hunter2'",
				Category: "dictionary",
				Severity: 3,
			},
		}
		public := toPublicIssues(sensitive, true)
		if len(public) != 1 {
			t.Fatalf("expected 1 issue, got %d", len(public))
		}
		if public[0].Message == sensitive[0].Message {
			t.Error("redact=true should modify the message containing a quoted word")
		}
		if !strings.Contains(public[0].Message, "***") {
			t.Errorf("redacted message should contain '***', got: %q", public[0].Message)
		}
	})
}

func TestNewChecker_UsesValidatedConfig(t *testing.T) {
	cfg := DefaultConfig()

	checker, err := NewChecker(cfg)
	if err != nil {
		t.Fatalf("NewChecker(DefaultConfig) returned error: %v", err)
	}

	result, err := checker.Check("P@ssw0rd123!")
	if err != nil {
		t.Fatalf("checker.Check returned error: %v", err)
	}
	if result.Score < 0 || result.Score > 100 {
		t.Errorf("checker result score out of range: %d", result.Score)
	}
}

func TestResolveVerdict_DefaultAndCustomThresholds(t *testing.T) {
	t.Run("default_thresholds", func(t *testing.T) {
		for _, score := range []int{0, 25, 50, 75, 90} {
			got := resolveVerdict(score, nil)
			want := scoring.Verdict(score)
			if got != string(want) {
				t.Errorf("resolveVerdict(%d, nil) = %q, want %q", score, got, want)
			}
		}
	})

	t.Run("custom_thresholds", func(t *testing.T) {
		vt := &VerdictThresholds{
			VeryWeakMax: 10,
			WeakMax:     20,
			OkayMax:     40,
			StrongMax:   70,
		}
		for _, score := range []int{5, 15, 30, 60, 90} {
			got := resolveVerdict(score, vt)
			want := scoring.VerdictWith(score, vt.VeryWeakMax, vt.WeakMax, vt.OkayMax, vt.StrongMax)
			if got != string(want) {
				t.Errorf("resolveVerdict(%d, custom) = %q, want %q", score, got, want)
			}
		}
	})
}

