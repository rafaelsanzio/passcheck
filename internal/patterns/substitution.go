package patterns

import (
	"fmt"
	"strings"

	"github.com/rafaelsanzio/passcheck/internal/leet"
)

// commonWeakWords is a small embedded list of well-known weak passwords
// and dictionary words used for immediate feedback during pattern detection.
// The dictionary package provides a more comprehensive wordlist.
var commonWeakWords = []string{
	"password",
	"admin",
	"login",
	"welcome",
	"master",
	"hello",
	"monkey",
	"dragon",
	"letmein",
	"qwerty",
	"iloveyou",
	"trustno",
	"sunshine",
	"princess",
	"football",
	"shadow",
	"michael",
	"superman",
	"batman",
	"access",
	"secret",
	"passw",
}

// checkSubstitution normalizes the password by reversing common leetspeak
// substitutions and then checks whether any well-known weak word appears
// in the normalized form.
//
// Example: "p@$$w0rd" → "password" → match.
func checkSubstitution(password string) []string {
	normalized := leet.Normalize(password)

	// No substitutions were made — nothing extra to report.
	if normalized == password {
		return nil
	}

	seen := make(map[string]bool)
	var issues []string

	for _, word := range commonWeakWords {
		if strings.Contains(normalized, word) && !seen[word] {
			seen[word] = true
			issues = append(issues, fmt.Sprintf(
				"Contains common word with substitution: '%s'", word,
			))
		}
	}

	return issues
}
