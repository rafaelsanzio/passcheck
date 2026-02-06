package scoring

import "testing"

// ---------------------------------------------------------------------------
// Calculate
// ---------------------------------------------------------------------------

func TestCalculate_ZeroEntropy(t *testing.T) {
	score := Calculate(0, "", IssueSet{})
	if score != 0 {
		t.Errorf("expected 0, got %d", score)
	}
}

func TestCalculate_PerfectEntropy_NoIssues(t *testing.T) {
	// 128 bits → base 100, strong password with 4 charsets and 18 chars.
	// Bonus: length 18-12=6 → +12, charset 4 types → +9. Total 121 → clamped 100.
	score := Calculate(128, "aB3!aB3!aB3!aB3!aB", IssueSet{})
	if score != 100 {
		t.Errorf("expected 100, got %d", score)
	}
}

func TestCalculate_HighEntropy_Capped(t *testing.T) {
	// 200 bits → base 156, bonuses push higher → clamped to 100.
	score := Calculate(200, "aB3!xYz9mKpL!qR2wV", IssueSet{})
	if score != 100 {
		t.Errorf("expected 100 (capped), got %d", score)
	}
}

func TestCalculate_RulesPenalty(t *testing.T) {
	// 64 bits → base 50, 2 rule issues → -10.
	// Password "ab" → length bonus 0, charset bonus 0 (1 set).
	issues := IssueSet{Rules: []string{"too short", "no upper"}}
	score := Calculate(64, "ab", issues)
	// 50 + 0 + 0 - 10 = 40
	if score != 40 {
		t.Errorf("expected 40, got %d", score)
	}
}

func TestCalculate_PatternsPenalty(t *testing.T) {
	// 64 bits → base 50, 1 pattern issue → -10.
	// Password "abcdefghijklmnop" → length bonus (16-12)×2=8, charset bonus 0 (1 set).
	issues := IssueSet{Patterns: []string{"keyboard pattern"}}
	score := Calculate(64, "abcdefghijklmnop", issues)
	// 50 + 8 + 0 - 10 = 48
	if score != 48 {
		t.Errorf("expected 48, got %d", score)
	}
}

func TestCalculate_DictionaryPenalty(t *testing.T) {
	// 64 bits → base 50, 1 dict issue → -15.
	// Password "ab" → no bonuses.
	issues := IssueSet{Dictionary: []string{"common password"}}
	score := Calculate(64, "ab", issues)
	// 50 + 0 + 0 - 15 = 35
	if score != 35 {
		t.Errorf("expected 35, got %d", score)
	}
}

func TestCalculate_MixedPenalties(t *testing.T) {
	// 80 bits → base 62.
	// Password "ab" → no bonuses.
	// 2 rules (-10) + 1 pattern (-10) + 1 dict (-15) = -35.
	issues := IssueSet{
		Rules:      []string{"r1", "r2"},
		Patterns:   []string{"p1"},
		Dictionary: []string{"d1"},
	}
	score := Calculate(80, "ab", issues)
	// 62 + 0 + 0 - 35 = 27
	if score != 27 {
		t.Errorf("expected 27, got %d", score)
	}
}

func TestCalculate_NeverBelowZero(t *testing.T) {
	issues := IssueSet{
		Rules:      make([]string, 10),
		Patterns:   make([]string, 10),
		Dictionary: make([]string, 10),
	}
	score := Calculate(10, "", issues)
	if score != 0 {
		t.Errorf("expected 0 (clamped), got %d", score)
	}
}

func TestCalculate_LengthBonus(t *testing.T) {
	// 50 base, password 16 chars (all lower) → length bonus (16-12)×2=8, charset bonus 0.
	score := Calculate(64, "abcdefghijklmnop", IssueSet{})
	// 50 + 8 + 0 = 58
	if score != 58 {
		t.Errorf("expected 58, got %d", score)
	}
}

func TestCalculate_LengthBonusCapped(t *testing.T) {
	// Password 30 chars → extra=18 → 18×2=36 → capped at 20.
	score := Calculate(64, "abcdefghijklmnopqrstuvwxyzabcd", IssueSet{})
	// 50 + 20 + 0 = 70
	if score != 70 {
		t.Errorf("expected 70, got %d", score)
	}
}

func TestCalculate_CharsetBonus(t *testing.T) {
	// 64 bits → base 50.
	// Password "aB3!" (4 chars, 4 charsets) → length bonus 0, charset bonus (4-1)×3=9.
	score := Calculate(64, "aB3!", IssueSet{})
	// 50 + 0 + 9 = 59
	if score != 59 {
		t.Errorf("expected 59, got %d", score)
	}
}

func TestCalculate_BothBonuses(t *testing.T) {
	// 64 bits → base 50.
	// Password "aB3!aB3!aB3!aB3!" (16 chars, 4 charsets).
	// Length bonus: (16-12)×2=8. Charset bonus: (4-1)×3=9.
	score := Calculate(64, "aB3!aB3!aB3!aB3!", IssueSet{})
	// 50 + 8 + 9 = 67
	if score != 67 {
		t.Errorf("expected 67, got %d", score)
	}
}

// ---------------------------------------------------------------------------
// lengthBonus
// ---------------------------------------------------------------------------

func TestLengthBonus(t *testing.T) {
	tests := []struct {
		name     string
		password string
		expected int
	}{
		{"empty", "", 0},
		{"below min", "abc", 0},
		{"exactly min", "abcdefghijkl", 0}, // 12 chars
		{"min + 1", "abcdefghijklm", 2},
		{"min + 5", "abcdefghijklmnopq", 10},
		{"min + 10", "abcdefghijklmnopqrstuv", 20},           // 22 chars → 10×2=20 = max
		{"min + 20", "abcdefghijklmnopqrstuvwxyzabcdef", 20}, // 32 chars → capped
		{"unicode", "hélloWörld!1234", 6},                    // 15 runes → (15-12)×2=6
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lengthBonus(tt.password); got != tt.expected {
				t.Errorf("lengthBonus(%q) = %d, want %d", tt.password, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// charsetBonus
// ---------------------------------------------------------------------------

func TestCharsetBonus(t *testing.T) {
	tests := []struct {
		name     string
		password string
		expected int
	}{
		{"empty", "", 0},
		{"1 set", "abcdef", 0},
		{"2 sets", "abcABC", 3},     // (2-1)×3=3
		{"3 sets", "abcABC123", 6},  // (3-1)×3=6
		{"4 sets", "abcABC123!", 9}, // (4-1)×3=9 = max
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := charsetBonus(tt.password); got != tt.expected {
				t.Errorf("charsetBonus(%q) = %d, want %d", tt.password, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

func TestVerdict(t *testing.T) {
	tests := []struct {
		score    int
		expected string
	}{
		{0, "Very Weak"},
		{10, "Very Weak"},
		{20, "Very Weak"},
		{21, "Weak"},
		{30, "Weak"},
		{40, "Weak"},
		{41, "Okay"},
		{50, "Okay"},
		{60, "Okay"},
		{61, "Strong"},
		{70, "Strong"},
		{80, "Strong"},
		{81, "Very Strong"},
		{90, "Very Strong"},
		{100, "Very Strong"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := Verdict(tt.score); got != tt.expected {
				t.Errorf("Verdict(%d) = %q, want %q", tt.score, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// IssueSet
// ---------------------------------------------------------------------------

func TestIssueSet_AllIssues(t *testing.T) {
	is := IssueSet{
		Rules:      []string{"r1", "r2"},
		Patterns:   []string{"p1"},
		Dictionary: []string{"d1", "d2"},
	}
	all := is.AllIssues()
	if len(all) != 5 {
		t.Errorf("expected 5 issues, got %d", len(all))
	}
	// Verify order: rules first, then patterns, then dictionary.
	expected := []string{"r1", "r2", "p1", "d1", "d2"}
	for i, want := range expected {
		if all[i] != want {
			t.Errorf("AllIssues()[%d] = %q, want %q", i, all[i], want)
		}
	}
}

func TestIssueSet_AllIssues_Empty(t *testing.T) {
	all := IssueSet{}.AllIssues()
	if len(all) != 0 {
		t.Errorf("expected 0 issues, got %d", len(all))
	}
}

// ---------------------------------------------------------------------------
// clamp
// ---------------------------------------------------------------------------

func TestClamp(t *testing.T) {
	tests := []struct {
		v, lo, hi, want int
	}{
		{50, 0, 100, 50},
		{-5, 0, 100, 0},
		{120, 0, 100, 100},
		{0, 0, 100, 0},
		{100, 0, 100, 100},
	}

	for _, tt := range tests {
		if got := clamp(tt.v, tt.lo, tt.hi); got != tt.want {
			t.Errorf("clamp(%d, %d, %d) = %d, want %d", tt.v, tt.lo, tt.hi, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// CalculateWith — custom minLength
// ---------------------------------------------------------------------------

func TestCalculateWith_CustomMinLength(t *testing.T) {
	// With minLength=8, a 12-char password gets (12-8)×2=8 length bonus.
	// 64 bits → base 50. 1 charset (lower) → charset bonus 0.
	score := CalculateWith(64, "abcdefghijkl", IssueSet{}, 8)
	// 50 + 8 + 0 = 58
	if score != 58 {
		t.Errorf("expected 58, got %d", score)
	}
}

func TestCalculateWith_DefaultMatchesCalculate(t *testing.T) {
	pw := "aB3!aB3!aB3!aB3!"
	issues := IssueSet{Rules: []string{"r1"}}

	got := CalculateWith(64, pw, issues, DefaultMinLength)
	want := Calculate(64, pw, issues)

	if got != want {
		t.Errorf("CalculateWith(DefaultMinLength) should match Calculate: got %d, want %d", got, want)
	}
}

func TestCalculateWith_HigherMinReducesBonus(t *testing.T) {
	pw := "abcdefghijklmnop" // 16 chars
	// With MinLength=12: bonus (16-12)×2=8.
	// With MinLength=16: bonus (16-16)×2=0.
	scoreDefault := CalculateWith(64, pw, IssueSet{}, 12)
	scoreHighMin := CalculateWith(64, pw, IssueSet{}, 16)

	if scoreHighMin >= scoreDefault {
		t.Errorf("higher minLength should reduce bonus: min12=%d, min16=%d", scoreDefault, scoreHighMin)
	}
}

// ---------------------------------------------------------------------------
// Integration: realistic password scenarios
// ---------------------------------------------------------------------------

func TestScoring_WeakPassword(t *testing.T) {
	// "password" → entropy ~37, base ~29. Short + missing charsets = 4 rule issues.
	// Dictionary match = 1 or more.
	issues := IssueSet{
		Rules:      []string{"too short", "no upper", "no digit", "no symbol"},
		Dictionary: []string{"common password"},
	}
	score := Calculate(37.6, "password", issues)
	if score > ThresholdWeak {
		t.Errorf("'password' should score ≤ %d, got %d", ThresholdWeak, score)
	}
}

func TestScoring_StrongPassword(t *testing.T) {
	// Random 19-char, 4 charsets, no issues.
	// Entropy ~124, base ~97. Length bonus 14, charset bonus 9.
	score := Calculate(124, "Xk9$mP2!vR7@nL4&wQz", IssueSet{})
	if score < ThresholdStrong {
		t.Errorf("strong random password should score > %d, got %d", ThresholdStrong, score)
	}
}

func TestScoring_ModeratePassword(t *testing.T) {
	// "MyPassw0rd12" → entropy ~78, base ~60. 12 chars (no length bonus).
	// 4 charsets → +9. Contains "password" word → 1 dict issue (-15).
	issues := IssueSet{
		Dictionary: []string{"contains common word"},
	}
	score := Calculate(78, "MyPassw0rd12", issues)
	// 60 + 0 + 9 - 15 = 54 → Okay range
	if score < ThresholdWeak || score > ThresholdStrong {
		t.Errorf("moderate password should score in Okay-Strong range, got %d", score)
	}
}
