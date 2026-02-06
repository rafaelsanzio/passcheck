// Command context demonstrates context-aware password checking: rejecting
// passwords that contain the username, email, or other user-specific terms.
//
// Run: go run ./examples/context
package main

import (
	"fmt"
	"log"

	"github.com/rafaelsanzio/passcheck"
)

func main() {
	cfg := passcheck.DefaultConfig()
	cfg.ContextWords = []string{
		"john",                  // username
		"john.doe@acme.com",     // email (local + domain parts are checked)
		"acme",                  // company name
	}

	// OK: no context words in password
	result, err := passcheck.CheckWithConfig("MySecret2024!", cfg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Password 'MySecret2024!': score=%d, verdict=%s\n", result.Score, result.Verdict)
	if len(result.Issues) > 0 {
		for _, iss := range result.Issues {
			fmt.Printf("  - [%s] %s\n", iss.Code, iss.Message)
		}
	} else {
		fmt.Println("  No issues.")
	}

	// Rejected: password contains username "john"
	result2, _ := passcheck.CheckWithConfig("John123!", cfg)
	fmt.Printf("\nPassword 'John123!': score=%d, verdict=%s\n", result2.Score, result2.Verdict)
	for _, iss := range result2.Issues {
		if iss.Category == "context" {
			fmt.Printf("  - [context] %s\n", iss.Message)
		}
	}
}
