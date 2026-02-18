// This example shows how to integrate the HIBP (Have I Been Pwned) breach
// database with passcheck. Only the first 5 characters of the password's
// SHA-1 hash are sent to the API (k-anonymity).
package main

import (
	"fmt"
	"log"

	"github.com/rafaelsanzio/passcheck"
	"github.com/rafaelsanzio/passcheck/hibp"
)

func main() {
	cfg := passcheck.DefaultConfig()
	cfg.HIBPMinOccurrences = 1

	client := hibp.NewClient()
	client.Cache = hibp.NewMemoryCacheWithTTL(256, hibp.DefaultCacheTTL)
	cfg.HIBPChecker = client

	result, err := passcheck.CheckWithConfig("password", cfg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Score: %d\n", result.Score)
	fmt.Printf("Verdict: %s\n", result.Verdict)
	for _, iss := range result.Issues {
		if iss.Code == passcheck.CodeHIBPBreached {
			fmt.Printf("  ⚠ %s\n", iss.Message)
		} else {
			fmt.Printf("  - %s\n", iss.Message)
		}
	}
}
