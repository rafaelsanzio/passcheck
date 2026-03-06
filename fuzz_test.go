package passcheck

import (
	"strings"
	"testing"
)

func FuzzCheckWithConfig(f *testing.F) {
	// Provide seed corpus covering different classes of inputs.
	f.Add("password")
	f.Add("P@$$w0rd123!")
	f.Add(strings.Repeat("a", 100))
	f.Add("    ")
	f.Add("correct horse battery staple")
	f.Add("admin@company.com")

	cfg := DefaultConfig()
	// Enable complex modes to ensure they don't panic on weird input
	cfg.PassphraseMode = true
	cfg.ConstantTimeMode = true
	cfg.ContextWords = []string{"admin", "company"}

	f.Fuzz(func(t *testing.T, input string) {
		_, _ = CheckWithConfig(input, cfg)
	})
}

func FuzzRedactMessage(f *testing.F) {
	// Seed corpus
	f.Add("Contains common word: 'dragon'")
	f.Add("Contains common password")
	f.Add("Contains specific context word: 'admin'")

	f.Fuzz(func(t *testing.T, msg string) {
		_ = redactMessage(msg)
	})
}
