# passcheck — Quick Start Guide

Get up and running with passcheck in 5 minutes.

- [Installation](#installation)
- [Basic check](#basic-check)
- [Validated Checker factory](#validated-checker-factory)
- [Secure byte-slice input](#secure-byte-slice-input)
- [Reading the result](#reading-the-result)
- [Custom configuration](#custom-configuration)
- [Policy presets](#policy-presets)
- [HIBP breach check](#hibp-breach-check)
- [Real-time / incremental feedback](#real-time--incremental-feedback)
- [HTTP middleware](#http-middleware)
- [Runnable examples](#runnable-examples)

---

## Installation

```bash
go get github.com/rafaelsanzio/passcheck
```

Requires Go 1.24+. The core module has **zero external dependencies**.

---

## Basic check

```go
package main

import (
    "fmt"
    "github.com/rafaelsanzio/passcheck"
)

func main() {
    result := passcheck.Check("MyP@ssw0rd123!")

    fmt.Printf("Score:       %d/100\n", result.Score)
    fmt.Printf("Verdict:     %s\n", result.Verdict)
    fmt.Printf("MeetsPolicy: %v\n", result.MeetsPolicy)
    fmt.Printf("Entropy:     %.1f bits\n", result.Entropy)

    for _, iss := range result.Issues {
        fmt.Printf("  [%s] %s\n", iss.Code, iss.Message)
    }
    for _, s := range result.Suggestions {
        fmt.Printf("  + %s\n", s)
    }
}
```

**`result.MeetsPolicy`** is `true` when all hard requirements (length, charset,
repeat limits) are satisfied. A password can meet policy and still score low
because of pattern or dictionary issues — two things the score alone cannot
distinguish.

---

## Validated Checker factory

Use `NewChecker` to validate the configuration once at startup and reuse the
`Checker` interface across multiple calls:

```go
cfg := passcheck.DefaultConfig()
cfg.MinLength = 14
cfg.RequireSymbol = true

checker, err := passcheck.NewChecker(cfg)
if err != nil {
    log.Fatalf("invalid config: %v", err)
}

// checker is safe for concurrent use.
result, err := checker.Check("CorrectHorseBatteryStaple!")
```

---

## Secure byte-slice input

When the password arrives as a `[]byte` (e.g. from an HTTP request body), use
`CheckBytes` to zero the buffer immediately after analysis, reducing the time
plaintext resides in memory:

```go
func handleRegister(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)

    var req struct{ Password []byte `json:"password"` }
    json.Unmarshal(body, &req)

    // req.Password is zeroed by CheckBytes after analysis.
    result := passcheck.CheckBytes(req.Password)
    if result.Score < 60 {
        http.Error(w, "password too weak", http.StatusBadRequest)
        return
    }
    // proceed with registration...
}
```

---

## Reading the result

```go
type Result struct {
    Score       int      // 0 (weakest) – 100 (strongest)
    Verdict     string   // "Very Weak" / "Weak" / "Okay" / "Strong" / "Very Strong"
    MeetsPolicy bool     // true when all hard policy requirements are satisfied
    Issues      []Issue  // prioritised, deduplicated problems
    Suggestions []string // positive feedback about strengths
    Entropy     float64  // estimated entropy in bits
}

type Issue struct {
    Code     string // e.g. "RULE_TOO_SHORT", "PATTERN_KEYBOARD", "DICT_COMMON_PASSWORD"
    Message  string // human-readable description
    Category string // "rule", "pattern", "dictionary", "context", "breach"
    Severity int    // 1 (low) – 3 (high)
}
```

Switch on `Issue.Code` for programmatic handling:

```go
for _, iss := range result.Issues {
    switch iss.Code {
    case passcheck.CodeRuleTooShort:
        // redirect user to lengthen password
    case passcheck.CodeDictCommonPassword:
        // warn: password is on a common list
    case passcheck.CodeHIBPBreached:
        // warn: password found in a breach database
    }
}
```

---

## Custom configuration

```go
cfg := passcheck.DefaultConfig()
cfg.MinLength = 8              // relax length requirement
cfg.RequireSymbol = false      // symbols optional
cfg.MaxIssues = 10             // surface more feedback
cfg.ContextWords = []string{   // reject passwords derived from user data
    "alice",
    "alice@example.com",
    "acmecorp",
}
cfg.CustomPasswords = []string{"Summer2025!", "Welcome1"} // block common org passwords
cfg.RedactSensitive = true     // mask password substrings in issue messages (safe for logs)

result, err := passcheck.CheckWithConfig("mypassword", cfg)
if err != nil {
    log.Fatal(err) // cfg failed Validate()
}
```

### Configurable verdict thresholds

Override the score boundaries that map to verdict labels:

```go
cfg.VerdictThresholds = &passcheck.VerdictThresholds{
    VeryWeakMax: 30, // stricter — scores ≤ 30 are "Very Weak"
    WeakMax:     50,
    OkayMax:     70,
    StrongMax:   85,
}
```

---

## Policy presets

Drop-in configs for standard security policies:

```go
// NIST SP 800-63B — length first, no composition rules
result, _ := passcheck.CheckWithConfig("correct-horse-battery-staple", passcheck.NISTConfig())

// OWASP recommended — web apps and SaaS
result, _ := passcheck.CheckWithConfig("MySecret!", passcheck.OWASPConfig())

// PCI-DSS — payment card systems
result, _ := passcheck.CheckWithConfig("MyC0mpl3x!P@ss", passcheck.PCIDSSConfig())

// Enterprise — high-security environments
result, _ := passcheck.CheckWithConfig("Tr0ub4dor&3-Extra", passcheck.EnterpriseConfig())
```

---

## HIBP breach check

Check whether a password appears in known breach databases using k-anonymity
(only a 5-character SHA-1 hash prefix is sent; the full password is never
transmitted):

```go
import (
    "github.com/rafaelsanzio/passcheck"
    "github.com/rafaelsanzio/passcheck/hibp"
)

client := hibp.NewClient()
client.Cache = hibp.NewMemoryCacheWithTTL(256, hibp.DefaultCacheTTL)

cfg := passcheck.DefaultConfig()
cfg.HIBPChecker = client

result, _ := passcheck.CheckWithConfig("password", cfg)
for _, iss := range result.Issues {
    if iss.Code == passcheck.CodeHIBPBreached {
        fmt.Println("password found in breach database!")
    }
}
```

The client retries on HTTP 429 with exponential backoff and honours the
`Retry-After` header. On any network error the check is skipped gracefully and
the rest of the result is still returned.

---

## Real-time / incremental feedback

For strength meters that update on every keystroke, use the incremental API.
Pass the previous result to get a delta so the UI can skip redundant redraws:

```go
var lastResult *passcheck.Result

func onKeystroke(password string) {
    result, delta, err := passcheck.CheckIncrementalWithConfig(password, lastResult, cfg)
    if err != nil {
        return
    }
    if delta.ScoreChanged || delta.IssuesChanged {
        updateStrengthMeter(result)
    }
    lastResult = &result
}
```

Debounce the input (100–300 ms) before calling to limit CPU usage on every
keystroke.

---

## HTTP middleware

Protect registration endpoints with zero extra dependencies (net/http):

```go
import "github.com/rafaelsanzio/passcheck/middleware"

mux.Handle("/register", middleware.HTTP(middleware.Config{
    MinScore:      60,
    PasswordField: "password",
    OnFailure: func(issues []passcheck.Issue) error {
        log.Printf("weak password rejected: %d issues", len(issues))
        return nil
    },
}, registerHandler))
```

Framework-specific adapters are separate submodules — import only what you use:

```bash
go get github.com/rafaelsanzio/passcheck/middleware/gin
go get github.com/rafaelsanzio/passcheck/middleware/echo
go get github.com/rafaelsanzio/passcheck/middleware/fiber
```

```go
import passcheckgin "github.com/rafaelsanzio/passcheck/middleware/gin"

r.POST("/register",
    passcheckgin.Gin(middleware.Config{MinScore: 60}),
    registerHandler,
)
```

---

## Runnable examples

Each example in [`examples/`](../examples/) is a standalone `go run` program:

| Directory | What it demonstrates |
|-----------|----------------------|
| [`examples/basic`](../examples/basic/) | `Check`, score, verdict, issues, suggestions |
| [`examples/config`](../examples/config/) | Custom config, redaction, invalid config |
| [`examples/context`](../examples/context/) | Context-aware detection (username, email) |
| [`examples/presets`](../examples/presets/) | All 5 policy presets side by side |
| [`examples/hibp`](../examples/hibp/) | HIBP client, k-anonymity, cache |
| [`examples/middleware`](../examples/middleware/) | HTTP middleware with Chi, Echo, Gin, Fiber |
| [`examples/webserver`](../examples/webserver/) | Minimal HTTP server returning JSON result |

Run any example directly:

```bash
go run ./examples/basic
go run ./examples/config
go run ./examples/hibp   # requires internet access
```

Full API reference: [pkg.go.dev/github.com/rafaelsanzio/passcheck](https://pkg.go.dev/github.com/rafaelsanzio/passcheck)
