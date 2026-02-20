package passcheck

import (
	"testing"

	"github.com/rafaelsanzio/passcheck/internal/issue"
	"github.com/rafaelsanzio/passcheck/internal/scoring"
)

func TestConstantSynchronization(t *testing.T) {
	tests := []struct {
		name   string
		public string
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
}
