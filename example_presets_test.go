package passcheck_test

import (
	"fmt"

	"github.com/rafaelsanzio/passcheck"
)

// ExampleNISTConfig demonstrates NIST SP 800-63B compliant configuration.
func ExampleNISTConfig() {
	cfg := passcheck.NISTConfig()

	// NIST focuses on length, not composition
	result, _ := passcheck.CheckWithConfig("MySecret2024", cfg)
	fmt.Printf("Score: %d\n", result.Score)
	fmt.Printf("Verdict: %s\n", result.Verdict)

	// Output:
	// Score: 44
	// Verdict: Okay
}

// ExamplePCIDSSConfig demonstrates PCI-DSS v4.0 compliant configuration.
func ExamplePCIDSSConfig() {
	cfg := passcheck.PCIDSSConfig()

	// PCI-DSS requires strict complexity
	result, _ := passcheck.CheckWithConfig("MyC0mpl3x!P@ss2024", cfg)
	fmt.Printf("Score: %d\n", result.Score)
	fmt.Printf("Verdict: %s\n", result.Verdict)

	// Output:
	// Score: 100
	// Verdict: Very Strong
}

// ExampleOWASPConfig demonstrates OWASP recommended configuration.
func ExampleOWASPConfig() {
	cfg := passcheck.OWASPConfig()

	// OWASP balances security and usability
	result, _ := passcheck.CheckWithConfig("MyPassword2024", cfg)
	fmt.Printf("Score: %d\n", result.Score)
	fmt.Printf("Verdict: %s\n", result.Verdict)

	// Output:
	// Score: 44
	// Verdict: Okay
}

// ExampleEnterpriseConfig demonstrates strict enterprise configuration.
func ExampleEnterpriseConfig() {
	cfg := passcheck.EnterpriseConfig()

	// Enterprise requires maximum security
	result, _ := passcheck.CheckWithConfig("MyC0mplex!Enterpr1se@2024", cfg)
	fmt.Printf("Score: %d\n", result.Score)
	fmt.Printf("Verdict: %s\n", result.Verdict)

	// Output:
	// Score: 100
	// Verdict: Very Strong
}

// ExampleUserFriendlyConfig demonstrates user-friendly configuration.
func ExampleUserFriendlyConfig() {
	cfg := passcheck.UserFriendlyConfig()

	// User-friendly allows more flexibility
	result, _ := passcheck.CheckWithConfig("mypassword2024", cfg)
	fmt.Printf("Score: %d\n", result.Score)
	fmt.Printf("Verdict: %s\n", result.Verdict)

	// Output:
	// Score: 32
	// Verdict: Weak
}

// ExampleNISTConfig_withContext demonstrates combining NIST preset with context checking.
func ExampleNISTConfig_withContext() {
	cfg := passcheck.NISTConfig()
	cfg.ContextWords = []string{"john", "john.doe@acme.com"}

	// NIST + context-aware checking (password has no context-word matches)
	result, _ := passcheck.CheckWithConfig("MySecret2024", cfg)
	fmt.Printf("Has issues: %v\n", len(result.Issues) > 0)

	// Output:
	// Has issues: true
}
