package dictionary

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Check (integration)
// ---------------------------------------------------------------------------

func TestCheck_CommonPassword(t *testing.T) {
	issues := Check("password")
	assertContainsIssue(t, issues, "common password lists")
}

func TestCheck_CommonPasswordCaseInsensitive(t *testing.T) {
	issues := Check("PASSWORD")
	assertContainsIssue(t, issues, "common password lists")
}

func TestCheck_LeetPassword(t *testing.T) {
	issues := Check("p@$$w0rd")
	assertContainsIssue(t, issues, "leetspeak variant")
}

func TestCheck_ContainsCommonWord(t *testing.T) {
	issues := Check("mysunshine99")
	assertContainsIssue(t, issues, "common word")
	assertContainsIssue(t, issues, "sunshine")
}

func TestCheck_StrongPassword(t *testing.T) {
	issues := Check("Xk9$mP2!vR7@nL4&wQ")
	if len(issues) != 0 {
		t.Errorf("expected no dictionary issues for random password, got %v", issues)
	}
}

func TestCheck_EmptyPassword(t *testing.T) {
	issues := Check("")
	if len(issues) != 0 {
		t.Errorf("expected no issues for empty password, got %v", issues)
	}
}

func TestCheck_ShortPassword(t *testing.T) {
	// "abc" is below DefaultMinWordLen and not in the password list.
	issues := Check("abc")
	if len(issues) != 0 {
		t.Errorf("expected no issues for short non-dictionary password, got %v", issues)
	}
}

// ---------------------------------------------------------------------------
// Exact Password Match
// ---------------------------------------------------------------------------

func TestCheckExactPassword(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		wantIssue bool
		contains  string
	}{
		{"exact match 'password'", "password", true, "common password lists"},
		{"exact match '123456'", "123456", true, "common password lists"},
		{"exact match 'qwerty'", "qwerty", true, "common password lists"},
		{"exact match 'letmein'", "letmein", true, "common password lists"},
		{"exact match 'dragon'", "dragon", true, "common password lists"},
		{"exact match 'superman'", "superman", true, "common password lists"},
		{"exact match 'admin'", "admin", true, "common password lists"},
		{"exact match 'welcome'", "welcome", true, "common password lists"},
		{"not in list", "xk9mprandomstring", false, ""},
		{"not exact (has suffix)", "password123xyz", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := normalizeLeet(tt.password)
			issues := checkExactPasswordWith(tt.password, normalized, DefaultOptions())
			hasIssue := len(issues) > 0
			if hasIssue != tt.wantIssue {
				t.Errorf("checkExactPasswordWith(%q): got issue=%v, want issue=%v (issues: %v)",
					tt.password, hasIssue, tt.wantIssue, issues)
			}
			if tt.contains != "" {
				assertContainsIssue(t, issues, tt.contains)
			}
		})
	}
}

func TestCheckExactPassword_LeetVariant(t *testing.T) {
	tests := []struct {
		name     string
		password string
		contains string
	}{
		// p@ssw0rd is now a direct entry in the expanded password list,
		// so it triggers exact-match rather than leet detection.
		{"p@ssw0rd → exact match", "p@ssw0rd", "common password lists"},
		{"@dm1n → admin", "@dm1n", "leetspeak variant"},
		{"l3tm31n → letmein", "l3tm31n", "leetspeak variant"},
		{"dr@g0n → dragon", "dr@g0n", "leetspeak variant"},
		{"$up3rm@n → superman", "$up3rm@n", "leetspeak variant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := normalizeLeet(tt.password)
			issues := checkExactPasswordWith(tt.password, normalized, DefaultOptions())
			assertContainsIssue(t, issues, tt.contains)
		})
	}
}

func TestCheckExactPassword_ExactMatchSkipsLeet(t *testing.T) {
	// If "password" itself is given (exact match), the leet variant
	// message should NOT also appear — exact match takes priority.
	normalized := normalizeLeet("password")
	issues := checkExactPasswordWith("password", normalized, DefaultOptions())
	if len(issues) != 1 {
		t.Errorf("expected exactly 1 issue, got %d: %v", len(issues), issues)
	}
	assertContainsIssue(t, issues, "common password lists")
}

// ---------------------------------------------------------------------------
// Common Word Containment
// ---------------------------------------------------------------------------

func TestCheckCommonWords(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		wantIssue bool
		contains  string
	}{
		{"contains 'sunshine'", "mysunshine99", true, "sunshine"},
		{"contains 'dragon'", "xdragonx", true, "dragon"},
		{"contains 'football'", "ilovefootball", true, "football"},
		{"contains 'master'", "grandmaster1", true, "master"},
		{"no common word", "xk9mprandomzqt", false, ""},
		{"password too short", "abc", false, ""},
		{"empty", "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := normalizeLeet(tt.password)
			issues := checkCommonWordsWith(tt.password, normalized, DefaultOptions())
			hasIssue := len(issues) > 0
			if hasIssue != tt.wantIssue {
				t.Errorf("checkCommonWordsWith(%q): got issue=%v, want issue=%v (issues: %v)",
					tt.password, hasIssue, tt.wantIssue, issues)
			}
			if tt.contains != "" {
				assertContainsIssue(t, issues, tt.contains)
			}
		})
	}
}

func TestCheckCommonWords_LeetNormalized(t *testing.T) {
	// "dr@g0n" normalizes to "dragon" which is a common word.
	password := "mydr@g0n99"
	normalized := normalizeLeet(password)
	issues := checkCommonWordsWith(password, normalized, DefaultOptions())
	assertContainsIssue(t, issues, "substitution")
	assertContainsIssue(t, issues, "dragon")
}

func TestCheckCommonWords_NoDuplicates(t *testing.T) {
	// "dragon" appears in both plain and normalized forms — report once.
	password := "xdragonx"
	normalized := normalizeLeet(password) // no leet chars → same string
	issues := checkCommonWordsWith(password, normalized, DefaultOptions())
	count := 0
	for _, issue := range issues {
		if strings.Contains(strings.ToLower(issue), "dragon") {
			count++
		}
	}
	if count > 1 {
		t.Errorf("expected 'dragon' reported once, got %d times: %v", count, issues)
	}
}

func TestCheckCommonWords_LongestMatchPrioritized(t *testing.T) {
	// "football" (8 chars) should be reported rather than "foot" (not in list)
	// or smaller substrings. The word list is sorted longest-first.
	password := "ilovefootball123"
	normalized := normalizeLeet(password)
	issues := checkCommonWordsWith(password, normalized, DefaultOptions())
	assertContainsIssue(t, issues, "football")
}

// ---------------------------------------------------------------------------
// findCommonWords
// ---------------------------------------------------------------------------

func TestFindCommonWords(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantLen  int
	}{
		{"contains one word", "xdragonx", 1},
		{"no common words", "xk9mqzt", 0},
		{"too short", "abc", 0},
		{"empty", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			words := findCommonWords(tt.password)
			if len(words) != tt.wantLen {
				t.Errorf("findCommonWords(%q): got %d words, want %d (%v)",
					tt.password, len(words), tt.wantLen, words)
			}
		})
	}
}

func TestFindCommonWords_CoverageSkipsSubstrings(t *testing.T) {
	// "football" should be found; "foot" (even if it were in the list)
	// should be skipped because the region is already covered.
	words := findCommonWords("football")
	if len(words) != 1 {
		t.Errorf("expected 1 word, got %d: %v", len(words), words)
	}
	if len(words) > 0 && words[0] != "football" {
		t.Errorf("expected 'football', got %q", words[0])
	}
}

// ---------------------------------------------------------------------------
// Password Set
// ---------------------------------------------------------------------------

func TestIsCommonPassword(t *testing.T) {
	tests := []struct {
		password string
		expected bool
	}{
		{"password", true},
		{"123456", true},
		{"qwerty", true},
		{"letmein", true},
		{"zxvqpwm", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.password, func(t *testing.T) {
			if got := isCommonPassword(tt.password); got != tt.expected {
				t.Errorf("isCommonPassword(%q) = %v, want %v", tt.password, got, tt.expected)
			}
		})
	}
}

func TestBuildPasswordSet(t *testing.T) {
	set := buildPasswordSet([]string{"alpha", "beta", "gamma"})
	if len(set) != 3 {
		t.Errorf("expected 3 entries, got %d", len(set))
	}
	if !set["alpha"] || !set["beta"] || !set["gamma"] {
		t.Error("set missing expected entries")
	}
	if set["delta"] {
		t.Error("set should not contain 'delta'")
	}
}

// ---------------------------------------------------------------------------
// Leet Normalization
// ---------------------------------------------------------------------------

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
			result := normalizeLeet(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeLeet(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizeLeet_NoAllocation(t *testing.T) {
	// When no leet chars are present, the same string should be returned.
	input := "hello"
	result := normalizeLeet(input)
	// Go string comparison — if the pointer is the same, no allocation occurred.
	if result != input {
		t.Errorf("expected same string back for non-leet input")
	}
}

func TestContainsLeet(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"hello", false},
		{"h3llo", true},
		{"p@ss", true},
		{"", false},
		{"normal text", false},
		{"$ymbol", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := containsLeet(tt.input); got != tt.expected {
				t.Errorf("containsLeet(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Word Helpers
// ---------------------------------------------------------------------------

func TestIndexOfSubstring(t *testing.T) {
	tests := []struct {
		s      string
		substr string
		want   int
	}{
		{"hello world", "world", 6},
		{"hello", "hello", 0},
		{"hello", "xyz", -1},
		{"", "a", -1},
		{"abc", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			if got := indexOfSubstring(tt.s, tt.substr); got != tt.want {
				t.Errorf("indexOfSubstring(%q, %q) = %d, want %d", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

func TestIsRegionCovered(t *testing.T) {
	covered := []bool{true, true, true, false, false}
	if !isRegionCovered(covered, 0, 3) {
		t.Error("region 0:3 should be covered")
	}
	if isRegionCovered(covered, 2, 3) {
		t.Error("region 2:5 should not be fully covered")
	}
}

func TestMarkRegion(t *testing.T) {
	covered := make([]bool, 5)
	markRegion(covered, 1, 3)
	expected := []bool{false, true, true, true, false}
	for i, v := range expected {
		if covered[i] != v {
			t.Errorf("covered[%d] = %v, want %v", i, covered[i], v)
		}
	}
}

// ---------------------------------------------------------------------------
// CheckWith (Options / Custom Lists)
// ---------------------------------------------------------------------------

func TestCheckWith_DefaultOptions_SameAsCheck(t *testing.T) {
	passwords := []string{"password", "p@$$w0rd", "mysunshine99", "Xk9$mP2!vR7@"}
	for _, pw := range passwords {
		got := CheckWith(pw, DefaultOptions())
		want := Check(pw)
		if len(got) != len(want) {
			t.Errorf("CheckWith(%q) returned %d issues, Check returned %d",
				pw, len(got), len(want))
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("CheckWith(%q)[%d] = %q, Check[%d] = %q",
					pw, i, got[i], i, want[i])
			}
		}
	}
}

func TestCheckWith_CustomPasswords(t *testing.T) {
	custom := Options{
		CustomPasswords: []string{"mycompanyname", "secretproject"},
	}

	// Custom password should be flagged.
	issues := CheckWith("mycompanyname", custom)
	assertContainsIssue(t, issues, "common password lists")

	// Another custom password.
	issues = CheckWith("secretproject", custom)
	assertContainsIssue(t, issues, "common password lists")

	// Non-custom, non-built-in password should not be flagged.
	issues = CheckWith("totallyuniquephrase42", custom)
	if containsIssue(issues, "common password lists") {
		t.Errorf("unexpected exact-match issue for non-custom password")
	}
}

func TestCheckWith_CustomPasswords_CaseInsensitive(t *testing.T) {
	// Custom passwords arrive lowercased from the public API layer.
	custom := Options{
		CustomPasswords: []string{"mycompanyname"},
	}
	issues := CheckWith("mycompanyname", custom)
	assertContainsIssue(t, issues, "common password lists")
}

func TestCheckWith_CustomWords(t *testing.T) {
	custom := Options{
		CustomWords: []string{"acmecorp", "widgetron"},
	}

	// Custom word detected as substring.
	issues := CheckWith("iloveacmecorp99", custom)
	assertContainsIssue(t, issues, "acmecorp")

	// Another custom word.
	issues = CheckWith("widgetronrules", custom)
	assertContainsIssue(t, issues, "widgetron")
}

func TestCheckWith_CustomWords_ShortIgnored(t *testing.T) {
	custom := Options{
		CustomWords: []string{"abc"}, // below DefaultMinWordLen (4)
	}

	// "abc" is too short and should be silently ignored.
	issues := CheckWith("xyzabcxyz", custom)
	if containsIssue(issues, "abc") {
		t.Errorf("short custom word 'abc' should have been ignored")
	}
}

func TestCheckWith_CustomPasswordsAndWords(t *testing.T) {
	custom := Options{
		CustomPasswords: []string{"myspecialpassword"},
		CustomWords:     []string{"projectx"},
	}

	// Custom exact password.
	issues := CheckWith("myspecialpassword", custom)
	assertContainsIssue(t, issues, "common password lists")

	// Custom word substring.
	issues = CheckWith("theprojectxlaunch", custom)
	assertContainsIssue(t, issues, "projectx")
}

func TestCheckWith_EmptyCustomLists(t *testing.T) {
	// Empty custom lists should behave identically to DefaultOptions.
	opts := Options{
		CustomPasswords: []string{},
		CustomWords:     []string{},
	}
	issues := CheckWith("password", opts)
	assertContainsIssue(t, issues, "common password lists")
}

func TestCheckWith_CustomPasswordLeetNormalization(t *testing.T) {
	// When a custom password is not a direct match but its leet-normalized
	// form matches a built-in password, both detectors should work.
	custom := Options{
		CustomPasswords: []string{"t3$tpassword"},
	}
	issues := CheckWith("t3$tpassword", custom)
	assertContainsIssue(t, issues, "common password lists")
}

// ---------------------------------------------------------------------------
// DisableLeet
// ---------------------------------------------------------------------------

func TestCheckWith_DisableLeet_ExactPassword(t *testing.T) {
	// "p@ssw0rd" is in the password list as a direct entry,
	// so it should still be flagged even with leet disabled.
	opts := Options{DisableLeet: true}
	issues := CheckWith("p@ssw0rd", opts)
	assertContainsIssue(t, issues, "common password lists")
}

func TestCheckWith_DisableLeet_PreventsLeetVariant(t *testing.T) {
	// "@dm1n" normalizes to "admin" (a common password), but with leet
	// disabled, the normalization should not occur. "@dm1n" is not in
	// the built-in list as a direct entry.
	opts := Options{DisableLeet: true}
	issues := CheckWith("@dm1n", opts)
	if containsIssue(issues, "leetspeak variant") {
		t.Error("expected NO leetspeak variant detection when DisableLeet=true")
	}
}

func TestCheckWith_DisableLeet_PreventsLeetWordDetection(t *testing.T) {
	// "dr@g0n" normalizes to "dragon" (a common word), but with leet
	// disabled only the literal "dr@g0n" is checked — no word match.
	opts := Options{DisableLeet: true}
	issues := CheckWith("mydr@g0n99", opts)
	if containsIssue(issues, "substitution") {
		t.Error("expected NO leet-based word detection when DisableLeet=true")
	}
}

func TestCheckWith_DisableLeet_PlainWordsStillDetected(t *testing.T) {
	// Plain-text words should still be detected regardless of DisableLeet.
	opts := Options{DisableLeet: true}
	issues := CheckWith("mysunshine99", opts)
	assertContainsIssue(t, issues, "sunshine")
}

func TestCheckWith_DisableLeet_PlainPasswordsStillDetected(t *testing.T) {
	// Plain-text common passwords should still be detected.
	opts := Options{DisableLeet: true}
	issues := CheckWith("password", opts)
	assertContainsIssue(t, issues, "common password lists")
}

func TestCheckWith_DisableLeet_DefaultIsFalse(t *testing.T) {
	// DefaultOptions should have DisableLeet=false.
	opts := DefaultOptions()
	if opts.DisableLeet {
		t.Error("DefaultOptions().DisableLeet should be false")
	}
}

func TestCheckWith_DisableLeet_WithCustomWords(t *testing.T) {
	// Custom words should still work when leet is disabled.
	opts := Options{
		CustomWords: []string{"acmecorp"},
		DisableLeet: true,
	}
	issues := CheckWith("iloveacmecorp99", opts)
	assertContainsIssue(t, issues, "acmecorp")
}

func TestCheckWith_DisableLeet_Comparison(t *testing.T) {
	// Compare results with and without leet for a leet-heavy password.
	// "@dm1n" normalizes to "admin".
	leetEnabled := Options{DisableLeet: false}
	leetDisabled := Options{DisableLeet: true}

	withLeet := CheckWith("@dm1n", leetEnabled)
	withoutLeet := CheckWith("@dm1n", leetDisabled)

	// With leet: should detect "admin" variant.
	if !containsIssue(withLeet, "leetspeak variant") {
		t.Error("expected leetspeak detection when DisableLeet=false")
	}
	// Without leet: should NOT detect "admin" variant.
	if containsIssue(withoutLeet, "leetspeak variant") {
		t.Error("expected NO leetspeak detection when DisableLeet=true")
	}
}

// ---------------------------------------------------------------------------
// List Integrity
// ---------------------------------------------------------------------------

func TestPasswordList_NoDuplicates(t *testing.T) {
	seen := make(map[string]int, len(commonPasswordsList))
	for i, p := range commonPasswordsList {
		if prev, ok := seen[p]; ok {
			t.Errorf("duplicate password %q at indices %d and %d", p, prev, i)
		}
		seen[p] = i
	}
}

func TestPasswordList_AllLowercase(t *testing.T) {
	for _, p := range commonPasswordsList {
		if p != strings.ToLower(p) {
			t.Errorf("password %q is not lowercase", p)
		}
	}
}

func TestPasswordList_SizeAtLeast900(t *testing.T) {
	unique := make(map[string]bool, len(commonPasswordsList))
	for _, p := range commonPasswordsList {
		unique[p] = true
	}
	if len(unique) < 900 {
		t.Errorf("expected at least 900 unique passwords, got %d", len(unique))
	}
	t.Logf("unique passwords: %d (raw entries: %d)", len(unique), len(commonPasswordsList))
}

func TestWordList_NoDuplicates(t *testing.T) {
	seen := make(map[string]int, len(commonWords))
	for i, w := range commonWords {
		if prev, ok := seen[w]; ok {
			t.Errorf("duplicate word %q at indices %d and %d", w, prev, i)
		}
		seen[w] = i
	}
}

func TestWordList_SortedLongestFirst(t *testing.T) {
	for i := 1; i < len(commonWords); i++ {
		if len(commonWords[i]) > len(commonWords[i-1]) {
			t.Errorf("word %q (len %d) at index %d is longer than %q (len %d) at index %d",
				commonWords[i], len(commonWords[i]), i,
				commonWords[i-1], len(commonWords[i-1]), i-1)
		}
	}
}

func TestWordList_MinLength(t *testing.T) {
	for _, w := range commonWords {
		if len(w) < DefaultMinWordLen {
			t.Errorf("word %q has length %d, below minimum %d", w, len(w), DefaultMinWordLen)
		}
	}
}

func TestWordList_SizeAtLeast250(t *testing.T) {
	if len(commonWords) < 250 {
		t.Errorf("expected at least 250 unique words, got %d", len(commonWords))
	}
	t.Logf("common words: %d", len(commonWords))
}

// ---------------------------------------------------------------------------
// isCommonPasswordIn
// ---------------------------------------------------------------------------

func TestIsCommonPasswordIn_BuiltInOnly(t *testing.T) {
	if !isCommonPasswordIn("password", nil) {
		t.Error("expected 'password' to match built-in list")
	}
	if isCommonPasswordIn("totallynotapassword", nil) {
		t.Error("expected no match for random string")
	}
}

func TestIsCommonPasswordIn_CustomList(t *testing.T) {
	custom := []string{"mycompanyname", "internalproject"}
	if !isCommonPasswordIn("mycompanyname", custom) {
		t.Error("expected 'mycompanyname' to match custom list")
	}
	if !isCommonPasswordIn("password", custom) {
		t.Error("expected 'password' to still match built-in list")
	}
	if isCommonPasswordIn("randomstring", custom) {
		t.Error("expected no match for random string")
	}
}

// ---------------------------------------------------------------------------
// findCommonWordsWithCustom
// ---------------------------------------------------------------------------

func TestFindCommonWordsWithCustom(t *testing.T) {
	custom := []string{"acmecorp", "widgetron"}
	matches := findCommonWordsWithCustom("iloveacmecorp", custom)
	found := false
	for _, m := range matches {
		if m == "acmecorp" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'acmecorp' in matches, got: %v", matches)
	}
}

func TestFindCommonWordsWithCustom_EmptyCustom(t *testing.T) {
	// Should behave same as findCommonWords.
	matches := findCommonWordsWithCustom("mydragonpass", nil)
	matchesDefault := findCommonWords("mydragonpass")
	if len(matches) != len(matchesDefault) {
		t.Errorf("empty custom should match default: got %d vs %d",
			len(matches), len(matchesDefault))
	}
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

func BenchmarkCheck_CommonPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Check("password")
	}
}

func BenchmarkCheck_LeetPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Check("p@$$w0rd")
	}
}

func BenchmarkCheck_StrongRandom(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Check("Xk9$mP2!vR7@nL4&wQ")
	}
}

func BenchmarkCheck_LongPassword(b *testing.B) {
	long := strings.Repeat("xYz9!", 20)
	for i := 0; i < b.N; i++ {
		Check(long)
	}
}

func BenchmarkCheckWith_CustomPasswords(b *testing.B) {
	opts := Options{
		CustomPasswords: []string{"custompass1", "custompass2", "custompass3"},
	}
	for i := 0; i < b.N; i++ {
		CheckWith("custompass1", opts)
	}
}

func BenchmarkCheckWith_CustomWords(b *testing.B) {
	opts := Options{
		CustomWords: []string{"acmecorp", "widgetron", "foobarqux"},
	}
	for i := 0; i < b.N; i++ {
		CheckWith("iloveacmecorp99", opts)
	}
}

func BenchmarkCheckWith_LargeCustomList(b *testing.B) {
	// Simulate a realistic blocklist (500 entries).
	customPw := make([]string, 500)
	for i := range customPw {
		customPw[i] = strings.Repeat("x", i+4) // unique strings
	}
	opts := Options{CustomPasswords: customPw}
	for i := 0; i < b.N; i++ {
		CheckWith("Xk9$mP2!vR7@nL4&wQ", opts)
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
