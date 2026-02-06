// Command middleware demonstrates the passcheck HTTP middleware for protecting
// password-related endpoints (registration, password change, etc.).
//
// This example shows:
//   - Basic middleware usage with net/http (zero dependencies)
//   - Both form and JSON body support
//   - Custom configuration (minimum score, password field name)
//   - OnFailure hook for logging rejected passwords
//
// Run: go run ./examples/middleware
//
// Test:
//   curl -X POST http://localhost:8080/register \
//     -H 'Content-Type: application/json' \
//     -d '{"password":"weak123"}'
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/rafaelsanzio/passcheck"
	"github.com/rafaelsanzio/passcheck/middleware"
)

func main() {
	// Configure middleware: require score ≥ 60 (Okay or stronger)
	cfg := middleware.Config{
		MinScore:      60,
		PasswordField: "password",
		OnFailure: func(issues []passcheck.Issue) error {
			// Optional: log rejected passwords (for monitoring/metrics)
			log.Printf("Password rejected: %d issue(s)", len(issues))
			return nil
		},
	}

	mux := http.NewServeMux()
	
	// Wrap the registration handler with middleware
	mux.Handle("/register", middleware.HTTP(cfg, http.HandlerFunc(handleRegister)))
	
	// Health check (no middleware)
	mux.HandleFunc("/health", handleHealth)

	addr := ":8080"
	fmt.Printf("Server listening on %s\n", addr)
	fmt.Println("Try: curl -X POST http://localhost:8080/register -H 'Content-Type: application/json' -d '{\"password\":\"weak\"}'")
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	// Password has already been validated by middleware
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Registration successful",
		"status":  "created",
	})
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
