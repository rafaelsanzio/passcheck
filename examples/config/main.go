// Command config demonstrates using passcheck with custom configuration.
//
// It compares the same password under different policy configurations to
// show how rules, thresholds, and reporting can be tuned.
//
// Usage:
//
//	go run ./examples/config
package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/rafaelsanzio/passcheck"
)

func main() {
	password := "MyDogMax1"

	// --- Default configuration ---
	fmt.Println("=== Default Config ===")
	printResult(password, passcheck.DefaultConfig())

	// --- Relaxed configuration ---
	relaxed := passcheck.DefaultConfig()
	relaxed.MinLength = 6
	relaxed.RequireSymbol = false
	relaxed.MaxRepeats = 5
	relaxed.MaxIssues = 10

	fmt.Println("=== Relaxed Config (MinLength=6, no symbol required) ===")
	printResult(password, relaxed)

	// --- Strict configuration ---
	strict := passcheck.DefaultConfig()
	strict.MinLength = 16
	strict.PatternMinLength = 3
	strict.MaxIssues = 0 // no limit on issues

	fmt.Println("=== Strict Config (MinLength=16, PatternMinLength=3) ===")
	printResult(password, strict)

	// --- Custom blocklist ---
	custom := passcheck.DefaultConfig()
	custom.MinLength = 6
	custom.RequireSymbol = false
	custom.CustomPasswords = []string{"MyDogMax1", "CompanyName2024"}
	custom.CustomWords = []string{"acmecorp", "projectx"}

	fmt.Println("=== Custom Blocklist (org-specific passwords & words) ===")
	printResult("MyDogMax1", custom)
	printResult("iloveacmecorp99", custom)

	// --- Validation demo ---
	fmt.Println("=== Invalid Config Demo ===")
	bad := passcheck.Config{MinLength: 0}
	if err := bad.Validate(); err != nil {
		fmt.Printf("Validation error: %v\n", err)
	}
}

func printResult(password string, cfg passcheck.Config) {
	result, err := passcheck.CheckWithConfig(password, cfg)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	fmt.Printf("Password: %s\n", password)
	fmt.Printf("  Score:   %d/100\n", result.Score)
	fmt.Printf("  Verdict: %s\n", result.Verdict)
	fmt.Printf("  Entropy: %.1f bits\n", result.Entropy)

	if len(result.Issues) > 0 {
		fmt.Printf("  Issues (%d):\n", len(result.Issues))
		for _, iss := range result.Issues {
			fmt.Printf("    - %s\n", iss.Message)
		}
	}

	if len(result.Suggestions) > 0 {
		fmt.Printf("  Strengths (%d):\n", len(result.Suggestions))
		for _, s := range result.Suggestions {
			fmt.Printf("    + %s\n", s)
		}
	}

	fmt.Println(strings.Repeat("─", 50))
}
