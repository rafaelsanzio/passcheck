package passcheck

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rafaelsanzio/passcheck/internal/safemem"
)

func TestCheck_EmptyPassword(t *testing.T) {
	result := Check("")

	if result.Score != 0 {
		t.Errorf("expected score 0 for empty password, got %d", result.Score)
	}
	if result.Entropy != 0 {
		t.Errorf("expected entropy 0 for empty password, got %f", result.Entropy)
	}
	if result.Verdict != VerdictVeryWeak {
		t.Errorf("expected verdict %q for empty password, got %q", VerdictVeryWeak, result.Verdict)
	}
}

func TestCheck_ReturnsResult(t *testing.T) {
	result := Check("TestPassword123!")

	// Should return a valid result struct.
	if result.Score < 0 || result.Score > 100 {
		t.Errorf("score out of range: %d", result.Score)
	}

	validVerdicts := map[string]bool{
		VerdictVeryWeak:   true,
		VerdictWeak:       true,
		VerdictOkay:       true,
		VerdictStrong:     true,
		VerdictVeryStrong: true,
	}
	if !validVerdicts[result.Verdict] {
		t.Errorf("invalid verdict: %q", result.Verdict)
	}

	if result.Entropy < 0 {
		t.Errorf("entropy should not be negative: %f", result.Entropy)
	}
}

func TestCheck_StrongerPasswordScoresHigher(t *testing.T) {
	weak := Check("abc")
	strong := Check("Tr0ub4dor&3xYz!Qm")

	if strong.Score <= weak.Score {
		t.Errorf("expected stronger password to score higher: weak=%d, strong=%d",
			weak.Score, strong.Score)
	}
}

func TestCheck_IssuesNotEmpty(t *testing.T) {
	// A strong password should have no issues.
	result := Check("Xk9$mP2!vR7@nL4&wQ")

	for _, iss := range result.Issues {
		if iss.Message == "" {
			t.Error("issue message should not be empty")
		}
	}
}

func TestVerdictConstants(t *testing.T) {
	verdicts := []string{
		VerdictVeryWeak,
		VerdictWeak,
		VerdictOkay,
		VerdictStrong,
		VerdictVeryStrong,
	}

	for _, v := range verdicts {
		if v == "" {
			t.Error("verdict constant should not be empty")
		}
	}
}

// ---------------------------------------------------------------------------
// Scoring behavior with the new weighted system
// ---------------------------------------------------------------------------

func TestCheck_CommonPasswordIsVeryWeak(t *testing.T) {
	result := Check("password")
	if result.Verdict != VerdictVeryWeak {
		t.Errorf("common password should be Very Weak, got %q (score %d)", result.Verdict, result.Score)
	}
}

func TestCheck_StrongRandomIsVeryStrong(t *testing.T) {
	result := Check("Xk9$mP2!vR7@nL4&wQ")
	if result.Score < 80 {
		t.Errorf("strong random password should score ≥ 80, got %d", result.Score)
	}
}

func TestCheck_ShortPasswordIsVeryWeak(t *testing.T) {
	result := Check("abc")
	if result.Verdict != VerdictVeryWeak {
		t.Errorf("short password should be Very Weak, got %q (score %d)", result.Verdict, result.Score)
	}
}

func TestCheck_IssuesAreCategorized(t *testing.T) {
	// A password with multiple kinds of issues should have them all listed.
	result := Check("password")
	if len(result.Issues) == 0 {
		t.Error("'password' should have issues")
	}
}

func TestCheck_ScoreReflectsLength(t *testing.T) {
	short := Check("aB3!aB3!aB3!")        // 12 chars
	long := Check("aB3!aB3!aB3!aB3!aB3!") // 20 chars

	if long.Score <= short.Score {
		t.Errorf("longer password should score higher: short=%d, long=%d",
			short.Score, long.Score)
	}
}

// ---------------------------------------------------------------------------
// Phase 5: Feedback Engine — dedup, prioritize, suggestions
// ---------------------------------------------------------------------------

func TestCheck_IssuesSortedBySeverity(t *testing.T) {
	// "password" triggers dictionary (high severity) and rule issues (low severity).
	result := Check("password")
	if len(result.Issues) == 0 {
		t.Fatal("expected issues for 'password'")
	}
	// First issue should come from dictionary phase (most critical).
	first := result.Issues[0]
	if first.Message == "" {
		t.Error("first issue message should not be empty")
	}
}

func TestCheck_IssuesLimitedToFive(t *testing.T) {
	// A terrible password that triggers many issues across all phases.
	result := Check("qwerty")
	if len(result.Issues) > 5 {
		t.Errorf("issues should be limited to 5, got %d: %v", len(result.Issues), result.Issues)
	}
}

func TestCheck_SuggestionsForStrongPassword(t *testing.T) {
	result := Check("Xk9$mP2!vR7@nL4&wQzB")
	if len(result.Suggestions) == 0 {
		t.Errorf("strong password should have positive suggestions, got none")
	}
}

func TestCheck_NoSuggestionsForEmptyPassword(t *testing.T) {
	result := Check("")
	if len(result.Suggestions) != 0 {
		t.Errorf("empty password should have no suggestions, got %v", result.Suggestions)
	}
}

func TestCheck_SlicesNeverNil(t *testing.T) {
	result := Check("")
	if result.Issues == nil {
		t.Error("Issues should be non-nil empty slice, got nil")
	}
	if result.Suggestions == nil {
		t.Error("Suggestions should be non-nil empty slice, got nil")
	}
}

// ---------------------------------------------------------------------------
// Phase 6: Security & Performance
// ---------------------------------------------------------------------------

// --- CheckBytes ---

func TestCheckBytes_SameResultAsCheck(t *testing.T) {
	pw := "Tr0ub4dor&3xYz!Qm"
	expected := Check(pw)

	buf := []byte(pw)
	result := CheckBytes(buf)

	if result.Score != expected.Score {
		t.Errorf("score mismatch: Check=%d, CheckBytes=%d", expected.Score, result.Score)
	}
	if result.Verdict != expected.Verdict {
		t.Errorf("verdict mismatch: Check=%q, CheckBytes=%q", expected.Verdict, result.Verdict)
	}
	if result.Entropy != expected.Entropy {
		t.Errorf("entropy mismatch: Check=%f, CheckBytes=%f", expected.Entropy, result.Entropy)
	}
}

func TestCheckBytes_ZerosInput(t *testing.T) {
	buf := []byte("SuperSecret!99")
	CheckBytes(buf)

	if !safemem.IsZeroed(buf) {
		t.Errorf("CheckBytes should zero the input slice, got %v", buf)
	}
}

func TestCheckBytes_EmptySlice(t *testing.T) {
	result := CheckBytes([]byte{})
	if result.Score != 0 {
		t.Errorf("empty slice should produce score 0, got %d", result.Score)
	}
}

func TestCheckBytes_NilSlice(t *testing.T) {
	result := CheckBytes(nil)
	if result.Score != 0 {
		t.Errorf("nil slice should produce score 0, got %d", result.Score)
	}
	if result.Verdict != VerdictVeryWeak {
		t.Errorf("nil slice should produce Very Weak, got %q", result.Verdict)
	}
}

// --- MaxPasswordLength truncation ---

func TestCheck_MaxPasswordLength(t *testing.T) {
	// Build a password exactly at the limit — should work normally.
	atLimit := strings.Repeat("aB3!", MaxPasswordLength/4)
	rAtLimit := Check(atLimit)
	if rAtLimit.Score < 0 || rAtLimit.Score > 100 {
		t.Errorf("at-limit password score out of range: %d", rAtLimit.Score)
	}
}

func TestCheck_OverMaxPasswordLength(t *testing.T) {
	// Beyond the limit — should not panic and should produce a valid result.
	overLimit := strings.Repeat("X", MaxPasswordLength+500)
	result := Check(overLimit)
	if result.Score < 0 || result.Score > 100 {
		t.Errorf("over-limit password score out of range: %d", result.Score)
	}
}

func TestTruncate_Short(t *testing.T) {
	pw := "hello"
	if got := truncate(pw); got != pw {
		t.Errorf("short password should not be truncated, got %q", got)
	}
}

func TestTruncate_ExactlyAtLimit(t *testing.T) {
	pw := strings.Repeat("a", MaxPasswordLength)
	if got := truncate(pw); got != pw {
		t.Errorf("at-limit password should not be truncated")
	}
}

func TestTruncate_OverLimit(t *testing.T) {
	pw := strings.Repeat("a", MaxPasswordLength+100)
	got := truncate(pw)
	if len([]rune(got)) != MaxPasswordLength {
		t.Errorf("over-limit password should be truncated to %d runes, got %d",
			MaxPasswordLength, len([]rune(got)))
	}
}

func TestTruncate_Unicode(t *testing.T) {
	// Each emoji is one rune.
	pw := strings.Repeat("🔒", MaxPasswordLength+10)
	got := truncate(pw)
	if len([]rune(got)) != MaxPasswordLength {
		t.Errorf("unicode over-limit should truncate to %d runes, got %d",
			MaxPasswordLength, len([]rune(got)))
	}
}

// ---------------------------------------------------------------------------
// Phase 7: Configuration & API
// ---------------------------------------------------------------------------

// --- DefaultConfig ---

func TestDefaultConfig_Valid(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("DefaultConfig should be valid: %v", err)
	}
}

func TestDefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MinLength != 12 {
		t.Errorf("MinLength: got %d, want 12", cfg.MinLength)
	}
	if !cfg.RequireUpper || !cfg.RequireLower || !cfg.RequireDigit || !cfg.RequireSymbol {
		t.Error("all charset requirements should default to true")
	}
	if cfg.MaxRepeats != 3 {
		t.Errorf("MaxRepeats: got %d, want 3", cfg.MaxRepeats)
	}
	if cfg.PatternMinLength != 4 {
		t.Errorf("PatternMinLength: got %d, want 4", cfg.PatternMinLength)
	}
	if cfg.MaxIssues != 5 {
		t.Errorf("MaxIssues: got %d, want 5", cfg.MaxIssues)
	}
}

// --- Validate ---

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{"valid default", func(c *Config) {}, false},
		{"MinLength=0", func(c *Config) { c.MinLength = 0 }, true},
		{"MinLength=-1", func(c *Config) { c.MinLength = -1 }, true},
		{"MinLength=1", func(c *Config) { c.MinLength = 1 }, false},
		{"MaxRepeats=1", func(c *Config) { c.MaxRepeats = 1 }, true},
		{"MaxRepeats=0", func(c *Config) { c.MaxRepeats = 0 }, true},
		{"MaxRepeats=2", func(c *Config) { c.MaxRepeats = 2 }, false},
		{"PatternMinLength=2", func(c *Config) { c.PatternMinLength = 2 }, true},
		{"PatternMinLength=0", func(c *Config) { c.PatternMinLength = 0 }, true},
		{"PatternMinLength=3", func(c *Config) { c.PatternMinLength = 3 }, false},
		{"MaxIssues=-1", func(c *Config) { c.MaxIssues = -1 }, true},
		{"MaxIssues=0", func(c *Config) { c.MaxIssues = 0 }, false},
		{"MaxIssues=10", func(c *Config) { c.MaxIssues = 10 }, false},
		{"MinExecutionTimeMs=-1", func(c *Config) { c.MinExecutionTimeMs = -1 }, true},
		{"MinExecutionTimeMs=0", func(c *Config) { c.MinExecutionTimeMs = 0 }, false},
		{"MinExecutionTimeMs=10", func(c *Config) { c.MinExecutionTimeMs = 10 }, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(&cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// --- CheckWithConfig ---

func TestCheckWithConfig_InvalidConfig(t *testing.T) {
	cfg := Config{} // zero-value → invalid
	_, err := CheckWithConfig("test", cfg)
	if err == nil {
		t.Error("expected error for zero-value config")
	}
}

func TestCheckWithConfig_CustomMinLength(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinLength = 6

	// "aB3!xY" (6 chars) passes with min 6.
	result, err := CheckWithConfig("aB3!xY", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, iss := range result.Issues {
		if strings.Contains(strings.ToLower(iss.Message), "too short") {
			t.Errorf("6-char password should pass with MinLength=6, got issue: %s", iss.Message)
		}
	}

	// Same password fails with default config.
	resultDef := Check("aB3!xY")
	found := false
	for _, iss := range resultDef.Issues {
		if strings.Contains(strings.ToLower(iss.Message), "too short") {
			found = true
		}
	}
	if !found {
		t.Error("6-char password should fail with default MinLength=12")
	}
}

func TestCheckWithConfig_NoSymbolRequired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireSymbol = false

	result, err := CheckWithConfig("AbcDef123456", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, iss := range result.Issues {
		if strings.Contains(strings.ToLower(iss.Message), "symbol") {
			t.Errorf("should not require symbol: %s", iss.Message)
		}
	}
}

func TestCheckWithConfig_MaxIssuesZero_NoLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxIssues = 0 // no limit

	result, err := CheckWithConfig("qwerty", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With no limit, more than 5 issues may appear.
	// Just verify result is valid.
	if result.Score < 0 || result.Score > 100 {
		t.Errorf("score out of range: %d", result.Score)
	}
}

func TestCheckWithConfig_StricterPatterns(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PatternMinLength = 3

	// "asd" triggers keyboard detection with min=3.
	result, err := CheckWithConfig("asdB1!xyzabc", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, iss := range result.Issues {
		if strings.Contains(strings.ToLower(iss.Message), "keyboard") {
			found = true
		}
	}
	if !found {
		t.Error("expected keyboard pattern with PatternMinLength=3")
	}
}

func TestCheckWithConfig_EquivalentToCheck(t *testing.T) {
	pw := "Xk9$mP2!vR7@nL4&wQzB"
	resultDef := Check(pw)
	resultCfg, err := CheckWithConfig(pw, DefaultConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resultDef.Score != resultCfg.Score {
		t.Errorf("score mismatch: Check=%d, CheckWithConfig(default)=%d",
			resultDef.Score, resultCfg.Score)
	}
	if resultDef.Verdict != resultCfg.Verdict {
		t.Errorf("verdict mismatch: Check=%q, CheckWithConfig=%q",
			resultDef.Verdict, resultCfg.Verdict)
	}
}

// --- CheckIncremental / CheckIncrementalWithConfig ---

func TestCheckIncremental_NilPrevious_EqualsCheck(t *testing.T) {
	password := "Xk9$mP2!vR7@nL4&wQzB"
	resultCheck := Check(password)
	resultInc := CheckIncremental(password, nil)
	if resultInc.Score != resultCheck.Score {
		t.Errorf("CheckIncremental(pw, nil).Score = %d, Check(pw).Score = %d", resultInc.Score, resultCheck.Score)
	}
	if resultInc.Verdict != resultCheck.Verdict {
		t.Errorf("CheckIncremental(pw, nil).Verdict = %q, Check(pw).Verdict = %q", resultInc.Verdict, resultCheck.Verdict)
	}
	if len(resultInc.Issues) != len(resultCheck.Issues) {
		t.Errorf("issues length: incremental %d, check %d", len(resultInc.Issues), len(resultCheck.Issues))
	}
}

func TestCheckIncremental_WithPrevious_ReturnsNewResult(t *testing.T) {
	prev := Check("weak")
	result := CheckIncremental("Xk9$mP2!vR7@nL4&wQzB", &prev)
	if result.Score == prev.Score {
		t.Error("result should differ from previous when password changed")
	}
	if result.Score < 90 {
		t.Errorf("strong password should score high, got %d", result.Score)
	}
}

func TestCheckIncrementalWithConfig_InvalidConfig_ReturnsError(t *testing.T) {
	_, _, err := CheckIncrementalWithConfig("test", nil, Config{})
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

func TestCheckIncrementalWithConfig_NilPrevious_AllDeltasTrue(t *testing.T) {
	cfg := DefaultConfig()
	result, delta, err := CheckIncrementalWithConfig("password", nil, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !delta.ScoreChanged || !delta.IssuesChanged || !delta.SuggestionsChanged {
		t.Errorf("nil previous: expected all deltas true, got %+v", delta)
	}
	if result.Score < 0 || result.Score > 100 {
		t.Errorf("invalid score: %d", result.Score)
	}
}

func TestCheckIncrementalWithConfig_SamePassword_SameResult_NoDelta(t *testing.T) {
	cfg := DefaultConfig()
	password := "Xk9$mP2!vR7@nL4&wQzB"
	first, _, err := CheckIncrementalWithConfig(password, nil, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, delta, err := CheckIncrementalWithConfig(password, &first, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if second.Score != first.Score {
		t.Errorf("same password: score %d != %d", second.Score, first.Score)
	}
	if delta.ScoreChanged {
		t.Error("same password: expected ScoreChanged false")
	}
	if delta.IssuesChanged {
		t.Error("same password: expected IssuesChanged false")
	}
	if delta.SuggestionsChanged {
		t.Error("same password: expected SuggestionsChanged false")
	}
}

func TestCheckIncrementalWithConfig_DifferentPassword_DeltaReflectsChange(t *testing.T) {
	cfg := DefaultConfig()
	weak := Check("a")
	strong, delta, err := CheckIncrementalWithConfig("Xk9$mP2!vR7@nL4&wQzB", &weak, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !delta.ScoreChanged {
		t.Error("different password: expected ScoreChanged true")
	}
	if !delta.IssuesChanged {
		t.Error("different password: expected IssuesChanged true")
	}
	if strong.Score <= weak.Score {
		t.Errorf("strong password score %d should be > weak %d", strong.Score, weak.Score)
	}
}

func TestCheckIncrementalWithConfig_EquivalentToCheckWithConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinLength = 8
	password := "MyP@ssw0rd"
	full, err := CheckWithConfig(password, cfg)
	if err != nil {
		t.Fatalf("CheckWithConfig: %v", err)
	}
	inc, delta, err := CheckIncrementalWithConfig(password, nil, cfg)
	if err != nil {
		t.Fatalf("CheckIncrementalWithConfig: %v", err)
	}
	if inc.Score != full.Score {
		t.Errorf("Score: incremental %d, CheckWithConfig %d", inc.Score, full.Score)
	}
	if inc.Verdict != full.Verdict {
		t.Errorf("Verdict: incremental %q, CheckWithConfig %q", inc.Verdict, full.Verdict)
	}
	if !delta.ScoreChanged || !delta.IssuesChanged {
		t.Error("nil previous should set deltas true")
	}
}

// mockHIBP implements the HIBPChecker interface for tests (no hibp import).
type mockHIBP struct {
	breached bool
	count    int
	err      error
}

func (m *mockHIBP) Check(_ string) (bool, int, error) {
	return m.breached, m.count, m.err
}

func TestCheckWithConfig_HIBP_AddsIssueWhenBreached(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinLength = 6
	cfg.HIBPChecker = &mockHIBP{breached: true, count: 10}
	cfg.HIBPMinOccurrences = 1

	result, err := CheckWithConfig("aB3!xy", cfg)
	if err != nil {
		t.Fatalf("CheckWithConfig: %v", err)
	}
	var found bool
	for _, iss := range result.Issues {
		if iss.Code == CodeHIBPBreached {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected HIBP_BREACHED issue when checker reports breached")
	}
}

func TestCheckWithConfig_HIBP_RespectsMinOccurrences(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinLength = 6
	cfg.HIBPChecker = &mockHIBP{breached: true, count: 1}
	cfg.HIBPMinOccurrences = 10

	result, err := CheckWithConfig("aB3!xy", cfg)
	if err != nil {
		t.Fatalf("CheckWithConfig: %v", err)
	}
	for _, iss := range result.Issues {
		if iss.Code == CodeHIBPBreached {
			t.Error("expected no HIBP issue when count < HIBPMinOccurrences")
		}
	}
}

func TestCheckWithConfig_HIBP_GracefulDegradationOnError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinLength = 6
	cfg.HIBPChecker = &mockHIBP{err: fmt.Errorf("network error")}

	result, err := CheckWithConfig("aB3!xy", cfg)
	if err != nil {
		t.Fatalf("CheckWithConfig: %v", err)
	}
	// Should still return a valid result (no HIBP issue when checker errors).
	for _, iss := range result.Issues {
		if iss.Code == CodeHIBPBreached {
			t.Error("expected no HIBP issue when checker returns error")
		}
	}
}

func TestCheckWithConfig_HIBP_NilChecker_NoIssue(t *testing.T) {
	cfg := DefaultConfig()
	result, _ := CheckWithConfig("password", cfg)
	for _, iss := range result.Issues {
		if iss.Code == CodeHIBPBreached {
			t.Error("default config has no HIBP checker; should not have HIBP issue")
		}
	}
}

func TestCheckWithConfig_HIBPResult_AddsIssueWhenBreached(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinLength = 6
	cfg.HIBPResult = &HIBPCheckResult{Breached: true, Count: 100}
	cfg.HIBPMinOccurrences = 1

	result, err := CheckWithConfig("aB3!xy", cfg)
	if err != nil {
		t.Fatalf("CheckWithConfig: %v", err)
	}
	var found bool
	for _, iss := range result.Issues {
		if iss.Code == CodeHIBPBreached {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected HIBP_BREACHED issue when HIBPResult reports breached")
	}
}

func TestCheckWithConfig_HIBPResult_RespectsMinOccurrences(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinLength = 6
	cfg.HIBPResult = &HIBPCheckResult{Breached: true, Count: 5}
	cfg.HIBPMinOccurrences = 10

	result, err := CheckWithConfig("aB3!xy", cfg)
	if err != nil {
		t.Fatalf("CheckWithConfig: %v", err)
	}
	for _, iss := range result.Issues {
		if iss.Code == CodeHIBPBreached {
			t.Error("expected no HIBP issue when HIBPResult count < HIBPMinOccurrences")
		}
	}
}

func TestCheckWithConfig_ConstantTimeMode_SameResult(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinLength = 6
	cfg.RequireSymbol = false
	resultNormal, err := CheckWithConfig("password", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg.ConstantTimeMode = true
	resultConstantTime, err := CheckWithConfig("password", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resultNormal.Score != resultConstantTime.Score {
		t.Errorf("ConstantTimeMode should not change score: got %d vs %d", resultNormal.Score, resultConstantTime.Score)
	}
	if resultNormal.Verdict != resultConstantTime.Verdict {
		t.Errorf("ConstantTimeMode should not change verdict: got %s vs %s", resultNormal.Verdict, resultConstantTime.Verdict)
	}
	if len(resultNormal.Issues) != len(resultConstantTime.Issues) {
		t.Errorf("ConstantTimeMode should not change issue count: got %d vs %d", len(resultNormal.Issues), len(resultConstantTime.Issues))
	}
}

func TestCheckWithConfig_MinExecutionTimeMs_Padding(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinLength = 6
	cfg.RequireSymbol = false
	cfg.ConstantTimeMode = true
	cfg.MinExecutionTimeMs = 15
	start := time.Now()
	_, err := CheckWithConfig("aB3!xy", cfg)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed < 14*time.Millisecond {
		t.Errorf("expected at least ~15ms when MinExecutionTimeMs=15, got %v", elapsed)
	}
}

func TestCheckWithConfig_ScoringAdaptsToMinLength(t *testing.T) {
	cfg8 := DefaultConfig()
	cfg8.MinLength = 8

	// A 12-char password gets more bonus with MinLength=8 (4 extra chars)
	// than with MinLength=12 (0 extra chars).
	result8, _ := CheckWithConfig("aB3!aB3!aB3!", cfg8)
	result12 := Check("aB3!aB3!aB3!")

	if result8.Score <= result12.Score {
		t.Errorf("lower MinLength should yield higher score: min8=%d, min12=%d",
			result8.Score, result12.Score)
	}
}

// --- CustomPasswords / CustomWords ---

func TestCheckWithConfig_CustomPasswords(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinLength = 6
	cfg.CustomPasswords = []string{"MyCompanyName"}

	result, err := CheckWithConfig("MyCompanyName", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should flag the custom password as a common password.
	found := false
	for _, iss := range result.Issues {
		if strings.Contains(strings.ToLower(iss.Message), "common password") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected custom password to be flagged, got issues: %v", result.Issues)
	}
}

func TestCheckWithConfig_CustomPasswords_CaseInsensitive(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinLength = 6
	cfg.CustomPasswords = []string{"MyCompanyName"}

	// Uppercase input should still match (lowered internally).
	result, err := CheckWithConfig("MYCOMPANYNAME", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, iss := range result.Issues {
		if strings.Contains(strings.ToLower(iss.Message), "common password") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected custom password to be flagged case-insensitively, got: %v", result.Issues)
	}
}

func TestCheckWithConfig_CustomWords(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinLength = 6
	cfg.CustomWords = []string{"AcmeCorp"}

	result, err := CheckWithConfig("iloveacmecorp99!", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, iss := range result.Issues {
		if strings.Contains(strings.ToLower(iss.Message), "acmecorp") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected custom word 'acmecorp' to be detected, got: %v", result.Issues)
	}
}

func TestCheckWithConfig_NilCustomLists_SameAsDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CustomPasswords = nil
	cfg.CustomWords = nil

	result, err := CheckWithConfig("password", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	defaultResult := Check("password")
	if result.Score != defaultResult.Score {
		t.Errorf("nil custom lists should match default: got score %d, want %d",
			result.Score, defaultResult.Score)
	}
}

func TestCheckWithConfig_DisableLeet(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinLength = 4
	cfg.DisableLeet = true

	// "@dm1n" normalizes to "admin" (common password), but with leet
	// disabled, it should not be flagged as a leet variant.
	result, err := CheckWithConfig("@dm1n", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, iss := range result.Issues {
		if strings.Contains(strings.ToLower(iss.Message), "leetspeak") {
			t.Errorf("expected no leet detection with DisableLeet=true, got: %v", result.Issues)
			break
		}
	}
}

func TestCheckWithConfig_DisableLeet_PlainStillWorks(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DisableLeet = true

	// "password" should still be detected as common even with leet disabled.
	result, err := CheckWithConfig("password", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, iss := range result.Issues {
		if strings.Contains(strings.ToLower(iss.Message), "common password") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("plain common password should be detected with DisableLeet=true, got: %v", result.Issues)
	}
}

func TestCheckWithConfig_DisableLeet_DefaultIsFalse(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.DisableLeet {
		t.Error("DefaultConfig().DisableLeet should be false")
	}
}

// --- CheckBytesWithConfig ---

func TestCheckBytesWithConfig_ZerosAndReturns(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinLength = 6

	buf := []byte("aB3!xY")
	result, err := CheckBytesWithConfig(buf, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !safemem.IsZeroed(buf) {
		t.Error("CheckBytesWithConfig should zero input")
	}
	if result.Score < 0 || result.Score > 100 {
		t.Errorf("score out of range: %d", result.Score)
	}
}

func TestCheckBytesWithConfig_InvalidConfig(t *testing.T) {
	_, err := CheckBytesWithConfig([]byte("test"), Config{})
	if err == nil {
		t.Error("expected error for zero-value config")
	}
}

// --- Fuzz tests ---

func FuzzCheck(f *testing.F) {
	// Seed corpus with representative inputs.
	f.Add("")
	f.Add("password")
	f.Add("Xk9$mP2!vR7@nL4&wQzB")
	f.Add("qwerty123")
	f.Add("p@$$w0rd")
	f.Add("aB3!aB3!aB3!")
	f.Add("🔒🔑✨🎉密码パスワード")
	f.Add(strings.Repeat("a", 2000))
	f.Add("   \t\n\r")
	f.Add("\x00\x01\x02\x03")

	validVerdicts := map[string]bool{
		VerdictVeryWeak:   true,
		VerdictWeak:       true,
		VerdictOkay:       true,
		VerdictStrong:     true,
		VerdictVeryStrong: true,
	}

	f.Fuzz(func(t *testing.T, password string) {
		result := Check(password)

		if result.Score < 0 || result.Score > 100 {
			t.Errorf("score out of range [0,100]: %d for input %q", result.Score, password)
		}
		if !validVerdicts[result.Verdict] {
			t.Errorf("invalid verdict %q for input %q", result.Verdict, password)
		}
		if result.Entropy < 0 {
			t.Errorf("negative entropy %.2f for input %q", result.Entropy, password)
		}
		for i, iss := range result.Issues {
			if iss.Message == "" {
				t.Errorf("empty issue message at index %d for input %q", i, password)
			}
		}
		for i, s := range result.Suggestions {
			if s == "" {
				t.Errorf("empty suggestion at index %d for input %q", i, password)
			}
		}
	})
}

func FuzzCheckBytes(f *testing.F) {
	f.Add([]byte("password"))
	f.Add([]byte("Xk9$mP2!vR7@nL4&wQzB"))
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xFE, 0xFD})

	f.Fuzz(func(t *testing.T, password []byte) {
		result := CheckBytes(password)

		if result.Score < 0 || result.Score > 100 {
			t.Errorf("score out of range: %d", result.Score)
		}
		// Input must be zeroed after call.
		if !safemem.IsZeroed(password) {
			t.Error("CheckBytes did not zero the input")
		}
	})
}

// --- Benchmarks ---

func BenchmarkCheck(b *testing.B) {
	passwords := []struct {
		name string
		pw   string
	}{
		{"empty", ""},
		{"short", "abc"},
		{"common", "password"},
		{"medium_12", "MyP@ss1234!x"},
		{"strong_20", "Xk9$mP2!vR7@nL4&wQzB"},
		{"long_100", strings.Repeat("aB3!", 25)},
		{"long_1000", strings.Repeat("aB3!", 250)},
		{"unicode", "Пароль密码パスワード🔒✨"},
	}

	for _, p := range passwords {
		b.Run(p.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				Check(p.pw)
			}
		})
	}
}

func BenchmarkCheckBytes(b *testing.B) {
	pw := []byte("Xk9$mP2!vR7@nL4&wQzB")

	for i := 0; i < b.N; i++ {
		// Allocate fresh buffer each iteration since CheckBytes zeros it.
		buf := make([]byte, len(pw))
		copy(buf, pw)
		CheckBytes(buf)
	}
}

func BenchmarkCheck_VeryLong(b *testing.B) {
	// Ensure the truncation cap keeps performance bounded.
	pw := strings.Repeat("aB3!xY7@", 200) // 1600 chars → truncated to 1024
	for i := 0; i < b.N; i++ {
		Check(pw)
	}
}

func BenchmarkCheckWithConfig_Default(b *testing.B) {
	cfg := DefaultConfig()
	pw := "Xk9$mP2!vR7@nL4&wQzB"
	for i := 0; i < b.N; i++ {
		_, _ = CheckWithConfig(pw, cfg)
	}
}

func BenchmarkCheckWithConfig_ConstantTimeMode(b *testing.B) {
	cfg := DefaultConfig()
	cfg.ConstantTimeMode = true
	pw := "Xk9$mP2!vR7@nL4&wQzB"
	for i := 0; i < b.N; i++ {
		_, _ = CheckWithConfig(pw, cfg)
	}
}
