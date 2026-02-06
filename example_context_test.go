package passcheck_test

import (
	"fmt"

	"github.com/rafaelsanzio/passcheck"
)

// ExampleCheckWithConfig_contextAware demonstrates context-aware password checking.
func ExampleCheckWithConfig_contextAware() {
	// Configure with user-specific context
	cfg := passcheck.DefaultConfig()
	cfg.ContextWords = []string{
		"john",                    // username
		"john.doe@acme-corp.com",  // email (auto-parsed)
		"acmecorp",                // company name
	}

	// This password contains the username "john"
	result, _ := passcheck.CheckWithConfig("John123!", cfg)
	
	// Check if context was detected
	hasContextIssue := false
	for _, iss := range result.Issues {
		if iss.Category == "context" {
			hasContextIssue = true
			fmt.Println("Detected:", iss.Message)
			break
		}
	}
	
	fmt.Printf("Contains personal info: %v\n", hasContextIssue)

	// Output:
	// Detected: Contains personal information: "john"
	// Contains personal info: true
}

// ExampleCheckWithConfig_contextAwareEmail demonstrates email extraction.
func ExampleCheckWithConfig_contextAwareEmail() {
	cfg := passcheck.DefaultConfig()
	cfg.ContextWords = []string{"john.doe@example.com"}

	// Password contains "doe" extracted from the email
	result, _ := passcheck.CheckWithConfig("MyDoe2024!", cfg)
	
	hasContextIssue := false
	for _, iss := range result.Issues {
		if iss.Category == "context" {
			hasContextIssue = true
			break
		}
	}
	
	fmt.Printf("Detected email component: %v\n", hasContextIssue)

	// Output:
	// Detected email component: true
}

// ExampleCheckWithConfig_contextAwareLeetspeak demonstrates leetspeak detection.
func ExampleCheckWithConfig_contextAwareLeetspeak() {
	cfg := passcheck.DefaultConfig()
	cfg.ContextWords = []string{"admin"}

	// Password contains "@dm1n" (leetspeak variant of "admin")
	result, _ := passcheck.CheckWithConfig("@dm1n2024!", cfg)
	
	hasContextIssue := false
	for _, iss := range result.Issues {
		if iss.Category == "context" {
			hasContextIssue = true
			break
		}
	}
	
	fmt.Printf("Detected leetspeak variant: %v\n", hasContextIssue)

	// Output:
	// Detected leetspeak variant: true
}
