package entropy

import (
	"math"
	"testing"
)

// ---------------------------------------------------------------------------
// Calculate
// ---------------------------------------------------------------------------

func TestCalculate_EmptyPassword(t *testing.T) {
	if result := Calculate(""); result != 0 {
		t.Errorf("expected 0 entropy for empty password, got %f", result)
	}
}

func TestCalculate_SingleCharSet(t *testing.T) {
	// "aaaa" → 4 runes, pool 26 → 4 * log2(26) ≈ 18.80
	result := Calculate("aaaa")
	expected := 4 * math.Log2(26)
	assertClose(t, expected, result, 0.01)
}

func TestCalculate_MixedCharSets(t *testing.T) {
	// "aA1!" → 4 runes, pool 94 → 4 * log2(94) ≈ 26.19
	result := Calculate("aA1!")
	expected := 4 * math.Log2(94)
	assertClose(t, expected, result, 0.01)
}

func TestCalculate_LongerPasswordHigherEntropy(t *testing.T) {
	short := Calculate("abc")
	long := Calculate("abcdefghijklmnop")
	if long <= short {
		t.Errorf("longer password should have higher entropy: short=%.2f, long=%.2f", short, long)
	}
}

func TestCalculate_MoreCharSetsHigherEntropy(t *testing.T) {
	lower := Calculate("abcdefgh")
	mixed := Calculate("aBcDeFgH")
	full := Calculate("aBcD1234")

	if mixed <= lower {
		t.Errorf("mixed case > lower: lower=%.2f, mixed=%.2f", lower, mixed)
	}
	if full <= mixed {
		t.Errorf("full charset > mixed: mixed=%.2f, full=%.2f", mixed, full)
	}
}

func TestCalculate_Unicode(t *testing.T) {
	// "héllo" is 5 runes (not 6 bytes).
	// Contains lower + symbol (é is classified as lowercase via unicode).
	result := Calculate("héllo")
	if result <= 0 {
		t.Errorf("expected positive entropy for unicode password, got %f", result)
	}

	// Ensure rune-count is used, not byte-count.
	runeEntropy := 5 * math.Log2(26) // 5 runes, lowercase pool
	assertClose(t, runeEntropy, result, 0.01)
}

func TestCalculate_OnlySpaces(t *testing.T) {
	// Spaces are filtered by the charset analysis (IsSpace → skipped).
	// Pool size is 0 → entropy should be 0.
	result := Calculate("    ")
	if result != 0 {
		t.Errorf("expected 0 entropy for only-spaces password, got %f", result)
	}
}

// ---------------------------------------------------------------------------
// AnalyzeCharsets
// ---------------------------------------------------------------------------

func TestAnalyzeCharsets(t *testing.T) {
	tests := []struct {
		name     string
		password string
		expected int // pool size
	}{
		{"lowercase only", "abcdef", 26},
		{"uppercase only", "ABCDEF", 26},
		{"digits only", "123456", 10},
		{"symbols only", "!@#$%^", 32},
		{"lower + upper", "abcABC", 52},
		{"lower + digits", "abc123", 36},
		{"all sets", "aA1!", 94},
		{"empty", "", 0},
		{"unicode lower", "ñéü", 26},
		{"unicode upper", "ÑÉÜ", 26},
		{"unicode digit", "٣٤٥", 10}, // Arabic-Indic digits
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := AnalyzeCharsets(tt.password)
			if got := info.PoolSize(); got != tt.expected {
				t.Errorf("PoolSize = %d, want %d", got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CharsetInfo
// ---------------------------------------------------------------------------

func TestCharsetInfo_SetCount(t *testing.T) {
	tests := []struct {
		info     CharsetInfo
		expected int
	}{
		{CharsetInfo{}, 0},
		{CharsetInfo{HasLower: true}, 1},
		{CharsetInfo{HasLower: true, HasUpper: true}, 2},
		{CharsetInfo{HasLower: true, HasUpper: true, HasDigit: true}, 3},
		{CharsetInfo{HasLower: true, HasUpper: true, HasDigit: true, HasSymbol: true}, 4},
	}

	for _, tt := range tests {
		if got := tt.info.SetCount(); got != tt.expected {
			t.Errorf("SetCount() = %d, want %d", got, tt.expected)
		}
	}
}

func TestCharsetInfo_PoolSize(t *testing.T) {
	tests := []struct {
		info     CharsetInfo
		expected int
	}{
		{CharsetInfo{}, 0},
		{CharsetInfo{HasLower: true}, 26},
		{CharsetInfo{HasDigit: true}, 10},
		{CharsetInfo{HasSymbol: true}, 32},
		{CharsetInfo{HasLower: true, HasUpper: true, HasDigit: true, HasSymbol: true}, 94},
	}

	for _, tt := range tests {
		if got := tt.info.PoolSize(); got != tt.expected {
			t.Errorf("PoolSize() = %d, want %d", got, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func assertClose(t *testing.T, expected, got, tolerance float64) {
	t.Helper()
	if math.Abs(got-expected) > tolerance {
		t.Errorf("expected %.4f ± %.4f, got %.4f", expected, tolerance, got)
	}
}
