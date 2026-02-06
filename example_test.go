package passcheck_test

import (
	"fmt"

	"github.com/rafaelsanzio/passcheck"
)

func ExampleCheck() {
	result := passcheck.Check("Xk9$mP2!vR7@nL4&wQzB")
	fmt.Printf("Score: %d\n", result.Score)
	fmt.Printf("Verdict: %s\n", result.Verdict)
	// Output:
	// Score: 100
	// Verdict: Very Strong
}

func ExampleCheck_weak() {
	result := passcheck.Check("password")
	fmt.Printf("Verdict: %s\n", result.Verdict)
	fmt.Printf("Issues: %d\n", len(result.Issues))
	// Output:
	// Verdict: Very Weak
	// Issues: 5
}

func ExampleCheckWithConfig() {
	cfg := passcheck.DefaultConfig()
	cfg.MinLength = 6
	cfg.RequireSymbol = false

	result, err := passcheck.CheckWithConfig("Hello1", cfg)
	if err != nil {
		fmt.Println("config error:", err)
		return
	}
	fmt.Printf("Score: %d\n", result.Score)
	fmt.Printf("Verdict: %s\n", result.Verdict)
	// Output:
	// Score: 8
	// Verdict: Very Weak
}

func ExampleCheckBytes() {
	buf := []byte("Xk9$mP2!vR7@nL4&wQzB")
	result := passcheck.CheckBytes(buf)
	fmt.Printf("Score: %d\n", result.Score)

	// buf is now zeroed.
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
		}
	}
	fmt.Printf("Input zeroed: %v\n", allZero)
	// Output:
	// Score: 100
	// Input zeroed: true
}

func ExampleDefaultConfig() {
	cfg := passcheck.DefaultConfig()
	fmt.Printf("MinLength: %d\n", cfg.MinLength)
	fmt.Printf("RequireUpper: %v\n", cfg.RequireUpper)
	fmt.Printf("MaxRepeats: %d\n", cfg.MaxRepeats)
	// Output:
	// MinLength: 12
	// RequireUpper: true
	// MaxRepeats: 3
}

func ExampleConfig_Validate() {
	cfg := passcheck.Config{MinLength: 0} // invalid
	err := cfg.Validate()
	fmt.Println(err)
	// Output:
	// passcheck: MinLength must be >= 1, got 0
}

func ExampleCheck_suggestions() {
	result := passcheck.Check("Xk9$mP2!vR7@nL4&wQzB")
	fmt.Printf("Suggestions: %d\n", len(result.Suggestions))
	for _, s := range result.Suggestions {
		fmt.Println(s)
	}
	// Output:
	// Suggestions: 5
	// Good length (20 characters)
	// Good character diversity (4 of 4 character types)
	// No common patterns detected
	// Not found in common password lists
	// Good entropy (131 bits)
}
