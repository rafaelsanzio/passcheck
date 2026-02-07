package passcheck_test

import (
	"fmt"

	"github.com/rafaelsanzio/passcheck"
	"github.com/rafaelsanzio/passcheck/hibp"
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

// ExampleResult_IssueMessages shows backward-compatible message slice from Result.Issues.
func ExampleResult_IssueMessages() {
	// Use a password that fails only length so we get one predictable issue.
	result := passcheck.Check("Xk9$m")
	messages := result.IssueMessages()
	fmt.Printf("Issue count: %d\n", len(messages))
	for _, msg := range messages {
		fmt.Println(msg)
	}
	// Output:
	// Issue count: 1
	// Too short (minimum 12 characters)
}

// ExampleCheckWithConfig_invalidConfig shows that an invalid config returns an error.
func ExampleCheckWithConfig_invalidConfig() {
	cfg := passcheck.Config{MinLength: -1}
	result, err := passcheck.CheckWithConfig("any", cfg)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("Score: %d\n", result.Score)
	// Output:
	// Error: passcheck: MinLength must be >= 1, got -1
}

// ExampleCheckBytesWithConfig runs CheckBytes with custom config and zeroes the buffer.
func ExampleCheckBytesWithConfig() {
	cfg := passcheck.DefaultConfig()
	cfg.MinLength = 8
	cfg.RequireSymbol = false
	buf := []byte("MyPass99")
	result, err := passcheck.CheckBytesWithConfig(buf, cfg)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("Score: %d\n", result.Score)
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	fmt.Printf("Input zeroed: %v\n", allZero)
	// Output:
	// Score: 12
	// Input zeroed: true
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

// ExampleIssue_codes shows programmatic handling of issues by code (e.g. for i18n or custom UI).
func ExampleIssue_codes() {
	result := passcheck.Check("short")
	for _, iss := range result.Issues {
		switch iss.Code {
		case passcheck.CodeRuleTooShort:
			fmt.Println("Rule: too short")
		case passcheck.CodeDictCommonPassword:
			fmt.Println("Dictionary: common password")
		case passcheck.CodeHIBPBreached:
			fmt.Println("Breach: found in HIBP")
		default:
			fmt.Printf("Other: %s\n", iss.Code)
		}
	}
	// Output:
	// Rule: too short
}

// ExampleCheckWithConfig_hibp shows breach checking using the hibp package (mock for deterministic output).
func ExampleCheckWithConfig_hibp() {
	cfg := passcheck.DefaultConfig()
	cfg.MinLength = 6
	cfg.RequireSymbol = false
	// In production use hibp.NewClient(); here a mock avoids network calls.
	cfg.HIBPChecker = &hibp.MockClient{
		CheckFunc: func(_ string) (bool, int, error) { return true, 42, nil },
	}
	result, err := passcheck.CheckWithConfig("aB3!xy", cfg)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	for _, iss := range result.Issues {
		if iss.Code == passcheck.CodeHIBPBreached {
			fmt.Println("Breach reported: true")
			return
		}
	}
	fmt.Println("Breach reported: false")
	// Output:
	// Breach reported: true
}

// ExampleCheckIncremental demonstrates real-time feedback: pass the previous
// result so the UI can update only when the score or issues change. Debounce
// input (e.g. 100–300 ms) when calling on every keystroke.
func ExampleCheckIncremental() {
	var lastResult *passcheck.Result
	onPasswordChange := func(password string) {
		result := passcheck.CheckIncremental(password, lastResult)
		fmt.Printf("Score: %d, Verdict: %s\n", result.Score, result.Verdict)
		lastResult = &result
	}
	onPasswordChange("a")
	onPasswordChange("ab")
	onPasswordChange("MyP@ssw0rd")
	// Output:
	// Score: 0, Verdict: Very Weak
	// Score: 0, Verdict: Very Weak
	// Score: 20, Verdict: Very Weak
}

// ExampleCheckIncrementalWithConfig shows how to use the delta to avoid
// redundant UI updates when nothing changed.
func ExampleCheckIncrementalWithConfig() {
	cfg := passcheck.DefaultConfig()
	var lastResult *passcheck.Result
	password := "Xk9$mP2!vR7@nL4&wQzB"
	result, delta, _ := passcheck.CheckIncrementalWithConfig(password, lastResult, cfg)
	fmt.Printf("Score: %d\n", result.Score)
	fmt.Printf("ScoreChanged: %v\n", delta.ScoreChanged)
	// Call again with same password and previous result; deltas are false.
	result2, delta2, _ := passcheck.CheckIncrementalWithConfig(password, &result, cfg)
	fmt.Printf("Same score: %v\n", result2.Score == result.Score)
	fmt.Printf("ScoreChanged: %v\n", delta2.ScoreChanged)
	// Output:
	// Score: 100
	// ScoreChanged: true
	// Same score: true
	// ScoreChanged: false
}
