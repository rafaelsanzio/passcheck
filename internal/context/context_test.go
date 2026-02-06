package context

import (
	"testing"

	"github.com/rafaelsanzio/passcheck/internal/issue"
)

func TestCheck(t *testing.T) {
	// Check should use DefaultOptions (no context words)
	result := Check("password123")
	if len(result) != 0 {
		t.Errorf("Check() with no context words should return empty, got %d issues", len(result))
	}
}

func TestCheckWith_NoContextWords(t *testing.T) {
	opts := Options{ContextWords: nil}
	result := CheckWith("password123", opts)
	if len(result) != 0 {
		t.Errorf("CheckWith() with nil context words should return empty, got %d issues", len(result))
	}

	opts = Options{ContextWords: []string{}}
	result = CheckWith("password123", opts)
	if len(result) != 0 {
		t.Errorf("CheckWith() with empty context words should return empty, got %d issues", len(result))
	}
}

func TestCheckWith_ExactMatch(t *testing.T) {
	tests := []struct {
		name     string
		password string
		context  []string
		wantHit  bool
	}{
		{
			name:     "exact match lowercase",
			password: "john123",
			context:  []string{"john"},
			wantHit:  true,
		},
		{
			name:     "exact match case insensitive",
			password: "JOHN123",
			context:  []string{"john"},
			wantHit:  true,
		},
		{
			name:     "exact match mixed case",
			password: "John123",
			context:  []string{"JOHN"},
			wantHit:  true,
		},
		{
			name:     "no match",
			password: "password123",
			context:  []string{"john"},
			wantHit:  false,
		},
		{
			name:     "substring match",
			password: "myjohn123",
			context:  []string{"john"},
			wantHit:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := Options{ContextWords: tt.context}
			result := CheckWith(tt.password, opts)

			if tt.wantHit && len(result) == 0 {
				t.Errorf("Expected context word to be detected, got no issues")
			}
			if !tt.wantHit && len(result) > 0 {
				t.Errorf("Expected no issues, got %d: %v", len(result), result)
			}
		})
	}
}

func TestCheckWith_LeetSpeakVariants(t *testing.T) {
	tests := []struct {
		name     string
		password string
		context  []string
		wantHit  bool
	}{
		{
			name:     "leet @ for a",
			password: "j0hn123",
			context:  []string{"john"},
			wantHit:  true,
		},
		{
			name:     "leet 0 for o",
			password: "j0hn123",
			context:  []string{"john"},
			wantHit:  true,
		},
		{
			name:     "leet 3 for e",
			password: "t3st123",
			context:  []string{"test"},
			wantHit:  true,
		},
		{
			name:     "leet $ for s",
			password: "te$t123",
			context:  []string{"test"},
			wantHit:  true,
		},
		{
			name:     "leet 1 for i",
			password: "adm1n",
			context:  []string{"admin"},
			wantHit:  true,
		},
		{
			name:     "multiple leet substitutions",
			password: "@dm1n",
			context:  []string{"admin"},
			wantHit:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := Options{ContextWords: tt.context}
			result := CheckWith(tt.password, opts)

			if tt.wantHit && len(result) == 0 {
				t.Errorf("Expected leetspeak variant to be detected, got no issues")
			}
			if !tt.wantHit && len(result) > 0 {
				t.Errorf("Expected no issues, got %d: %v", len(result), result)
			}
		})
	}
}

func TestCheckWith_EmailExtraction(t *testing.T) {
	tests := []struct {
		name     string
		password string
		context  []string
		wantHit  bool
	}{
		{
			name:     "email local part",
			password: "john123",
			context:  []string{"john.doe@example.com"},
			wantHit:  true,
		},
		{
			name:     "email domain",
			password: "example123",
			context:  []string{"john@example.com"},
			wantHit:  true,
		},
		{
			name:     "email first name",
			password: "john123",
			context:  []string{"john.doe@example.com"},
			wantHit:  true,
		},
		{
			name:     "email last name",
			password: "doe123",
			context:  []string{"john.doe@example.com"},
			wantHit:  true,
		},
		{
			name:     "email full local",
			password: "john.doe123",
			context:  []string{"john.doe@example.com"},
			wantHit:  true,
		},
		{
			name:     "email with hyphen",
			password: "acme123",
			context:  []string{"user@acme-corp.com"},
			wantHit:  true,
		},
		{
			name:     "email with underscore",
			password: "john123",
			context:  []string{"john_doe@example.com"},
			wantHit:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := Options{ContextWords: tt.context}
			result := CheckWith(tt.password, opts)

			if tt.wantHit && len(result) == 0 {
				t.Errorf("Expected email part to be detected, got no issues")
			}
			if !tt.wantHit && len(result) > 0 {
				t.Errorf("Expected no issues, got %d: %v", len(result), result)
			}
		})
	}
}

func TestCheckWith_MultipleContextWords(t *testing.T) {
	opts := Options{
		ContextWords: []string{"john", "acme", "admin"},
	}

	tests := []struct {
		name      string
		password  string
		wantCount int
	}{
		{
			name:      "no matches",
			password:  "SecureP@ss123!",
			wantCount: 0,
		},
		{
			name:      "one match",
			password:  "john123",
			wantCount: 1,
		},
		{
			name:      "two matches",
			password:  "johnacme123",
			wantCount: 2,
		},
		{
			name:      "all matches",
			password:  "johnacmeadmin",
			wantCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckWith(tt.password, opts)
			if len(result) != tt.wantCount {
				t.Errorf("Expected %d issues, got %d: %v", tt.wantCount, len(result), result)
			}
		})
	}
}

func TestCheckWith_ShortWords(t *testing.T) {
	// Words shorter than 3 characters should be ignored
	opts := Options{
		ContextWords: []string{"ab", "x", "jo"},
	}

	result := CheckWith("abxjo123", opts)
	if len(result) != 0 {
		t.Errorf("Short words (<3 chars) should be ignored, got %d issues", len(result))
	}
}

func TestCheckWith_Deduplication(t *testing.T) {
	// Same word should only be reported once
	opts := Options{
		ContextWords: []string{"john", "JOHN", "John"},
	}

	result := CheckWith("john123", opts)
	if len(result) != 1 {
		t.Errorf("Duplicate context words should be deduplicated, got %d issues", len(result))
	}
}

func TestCheckWith_IssueStructure(t *testing.T) {
	opts := Options{
		ContextWords: []string{"john"},
	}

	result := CheckWith("john123", opts)
	if len(result) != 1 {
		t.Fatalf("Expected 1 issue, got %d", len(result))
	}

	iss := result[0]
	if iss.Code != issue.CodeContextWord {
		t.Errorf("Expected code %s, got %s", issue.CodeContextWord, iss.Code)
	}
	if iss.Category != issue.CategoryContext {
		t.Errorf("Expected category %s, got %s", issue.CategoryContext, iss.Category)
	}
	if iss.Severity != issue.SeverityHigh {
		t.Errorf("Expected severity %d, got %d", issue.SeverityHigh, iss.Severity)
	}
	if iss.Message == "" {
		t.Error("Expected non-empty message")
	}
}

func TestNormalizeContextWord(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"John", "john"},
		{"JOHN", "john"},
		{"  john  ", "john"},
		{"John Doe", "john doe"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeContextWord(tt.input)
			if got != tt.want {
				t.Errorf("normalizeContextWord(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractEmailParts(t *testing.T) {
	tests := []struct {
		email string
		want  []string
	}{
		{
			email: "john@example.com",
			want:  []string{"john", "example", "com"},
		},
		{
			email: "john.doe@example.com",
			want:  []string{"john.doe", "john", "doe", "example", "com"},
		},
		{
			email: "john_doe@acme-corp.com",
			want:  []string{"john_doe", "john", "doe", "acme-corp", "acme", "corp", "com"},
		},
		{
			email: "user@sub.example.com",
			want:  []string{"user", "sub", "example", "com"},
		},
		{
			email: "invalid-email",
			want:  []string{"invalid-email"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			got := extractEmailParts(tt.email)
			if !equalStringSlices(got, tt.want) {
				t.Errorf("extractEmailParts(%q) = %v, want %v", tt.email, got, tt.want)
			}
		})
	}
}

func TestExtractWords(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{
			input: "john",
			want:  []string{"john"},
		},
		{
			input: "john.doe",
			want:  []string{"john.doe", "john", "doe"},
		},
		{
			input: "acme-corp",
			want:  []string{"acme-corp", "acme", "corp"},
		},
		{
			input: "john_doe",
			want:  []string{"john_doe", "john", "doe"},
		},
		{
			input: "john doe",
			want:  []string{"john doe", "john", "doe"},
		},
		{
			input: "john.doe@example.com",
			want:  []string{"john.doe", "john", "doe", "example", "com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractWords(tt.input)
			if !equalStringSlices(got, tt.want) {
				t.Errorf("extractWords(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestContainsContextWord(t *testing.T) {
	tests := []struct {
		name          string
		pwLower       string
		pwNormalized  string
		word          string
		want          bool
	}{
		{
			name:         "exact substring",
			pwLower:      "john123",
			pwNormalized: "john123",
			word:         "john",
			want:         true,
		},
		{
			name:         "no match",
			pwLower:      "password123",
			pwNormalized: "password123",
			word:         "john",
			want:         false,
		},
		{
			name:         "leetspeak match",
			pwLower:      "j0hn123",
			pwNormalized: "john123",
			word:         "john",
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsContextWord(tt.pwLower, tt.pwNormalized, tt.word)
			if got != tt.want {
				t.Errorf("containsContextWord() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Helper function to compare string slices (order-independent)
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	aMap := make(map[string]int)
	bMap := make(map[string]int)

	for _, s := range a {
		aMap[s]++
	}
	for _, s := range b {
		bMap[s]++
	}

	for k, v := range aMap {
		if bMap[k] != v {
			return false
		}
	}

	return true
}

// Benchmark tests
func BenchmarkCheckWith_NoContext(b *testing.B) {
	opts := Options{ContextWords: nil}
	password := "SecureP@ssw0rd123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckWith(password, opts)
	}
}

func BenchmarkCheckWith_SingleWord(b *testing.B) {
	opts := Options{ContextWords: []string{"john"}}
	password := "SecureP@ssw0rd123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckWith(password, opts)
	}
}

func BenchmarkCheckWith_TenWords(b *testing.B) {
	opts := Options{
		ContextWords: []string{
			"john", "doe", "acme", "corp", "admin",
			"test", "user", "example", "company", "project",
		},
	}
	password := "SecureP@ssw0rd123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckWith(password, opts)
	}
}

func BenchmarkCheckWith_Email(b *testing.B) {
	opts := Options{ContextWords: []string{"john.doe@acme-corp.com"}}
	password := "SecureP@ssw0rd123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckWith(password, opts)
	}
}

func BenchmarkCheckWith_WithMatch(b *testing.B) {
	opts := Options{ContextWords: []string{"john"}}
	password := "john123"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckWith(password, opts)
	}
}
