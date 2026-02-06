// Command webserver demonstrates passcheck as an HTTP password-checking service.
//
// It starts a web server on :8080 with two endpoints:
//
//   - POST /check — accepts a JSON body {"password":"..."} and returns
//     the passcheck.Result as JSON.
//   - GET  /health — returns a 200 OK health check.
//
// Usage:
//
//	go run ./examples/webserver
//
// Test with curl:
//
//	curl -s -X POST http://localhost:8080/check \
//	  -H 'Content-Type: application/json' \
//	  -d '{"password":"P@ssw0rd123!"}' | jq .
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/rafaelsanzio/passcheck"
)

type checkRequest struct {
	Password string `json:"password"`
}

type checkResponse struct {
	Score       int      `json:"score"`
	Verdict     string   `json:"verdict"`
	Entropy     float64  `json:"entropy"`
	Issues      []string `json:"issues"`
	Suggestions []string `json:"suggestions"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/check", handleCheck)
	mux.HandleFunc("/health", handleHealth)

	addr := ":8080"
	fmt.Printf("passcheck server listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req checkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.Password == "" {
		http.Error(w, `{"error":"password is required"}`, http.StatusBadRequest)
		return
	}

	result := passcheck.Check(req.Password)

	resp := checkResponse{
		Score:       result.Score,
		Verdict:     result.Verdict,
		Entropy:     result.Entropy,
		Issues:      result.Issues,      // guaranteed non-nil by passcheck
		Suggestions: result.Suggestions, // guaranteed non-nil by passcheck
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
