// Command basic demonstrates the core passcheck library API.
//
// It checks several passwords of varying strength and prints their
// score, verdict, issues, and suggestions.
//
// Usage:
//
//	go run ./examples/basic
package main

import (
	"fmt"
	"strings"

	"github.com/rafaelsanzio/passcheck"
)

func main() {
	passwords := []string{
		"",
		"password",
		"P@ssw0rd",
		"MyDog$N4me!sMax",
		"Xk9$mP2!vR7@nL4&wQzB",
	}

	for _, pw := range passwords {
		display := pw
		if display == "" {
			display = "(empty)"
		}

		result := passcheck.Check(pw)

		fmt.Printf("Password: %s\n", display)
		fmt.Printf("  Score:   %d/100\n", result.Score)
		fmt.Printf("  Verdict: %s\n", result.Verdict)
		fmt.Printf("  Entropy: %.1f bits\n", result.Entropy)

		if len(result.Issues) > 0 {
			fmt.Printf("  Issues:\n")
			for _, issue := range result.Issues {
				fmt.Printf("    - %s\n", issue)
			}
		}

		if len(result.Suggestions) > 0 {
			fmt.Printf("  Strengths:\n")
			for _, s := range result.Suggestions {
				fmt.Printf("    + %s\n", s)
			}
		}

		fmt.Println(strings.Repeat("─", 50))
	}
}
