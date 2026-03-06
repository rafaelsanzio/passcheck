package entropy

import (
	"testing"

	"github.com/rafaelsanzio/passcheck/internal/issue"
)

func BenchmarkCalculate_Simple(b *testing.B) {
	password := "Xk9$mP2!vR7@nL4&wQzB"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Calculate(password)
	}
}

func BenchmarkCalculateAdvanced(b *testing.B) {
	password := "qwerty123456"
	issues := []issue.Issue{
		issue.New(issue.CodePatternKeyboard, "Contains keyboard pattern: 'qwerty'", issue.CategoryPattern, issue.SeverityMed),
		issue.New(issue.CodePatternSequence, "Contains sequence: '123456'", issue.CategoryPattern, issue.SeverityMed),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CalculateAdvanced(password, issues)
	}
}

func BenchmarkCalculatePatternAware(b *testing.B) {
	password := "qwerty123456"
	issues := []issue.Issue{
		issue.New(issue.CodePatternKeyboard, "Contains keyboard pattern: 'qwerty'", issue.CategoryPattern, issue.SeverityMed),
		issue.New(issue.CodePatternSequence, "Contains sequence: '123456'", issue.CategoryPattern, issue.SeverityMed),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CalculatePatternAware(password, issues)
	}
}

func BenchmarkCalculateWithMode_Simple(b *testing.B) {
	password := "Xk9$mP2!vR7@nL4&wQzB"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CalculateWithMode(password, "simple", nil)
	}
}

func BenchmarkCalculateWithMode_Advanced(b *testing.B) {
	password := "qwerty123456"
	issues := []issue.Issue{
		issue.New(issue.CodePatternKeyboard, "Contains keyboard pattern: 'qwerty'", issue.CategoryPattern, issue.SeverityMed),
		issue.New(issue.CodePatternSequence, "Contains sequence: '123456'", issue.CategoryPattern, issue.SeverityMed),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CalculateWithMode(password, "advanced", issues)
	}
}

func BenchmarkCalculateWithMode_PatternAware(b *testing.B) {
	password := "qwerty123456"
	issues := []issue.Issue{
		issue.New(issue.CodePatternKeyboard, "Contains keyboard pattern: 'qwerty'", issue.CategoryPattern, issue.SeverityMed),
		issue.New(issue.CodePatternSequence, "Contains sequence: '123456'", issue.CategoryPattern, issue.SeverityMed),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CalculateWithMode(password, "pattern-aware", issues)
	}
}
