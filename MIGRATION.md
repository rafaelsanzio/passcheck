# Migration Guide

This document describes how to upgrade between versions of passcheck.

## v1.1.0 → v1.2.0

v1.2.0 is **backward-compatible** with v1.1.0. No code changes are required.

### Optional: Pre-computed HIBP result (WASM / browser)

If you build for WebAssembly and want to run the HIBP breach check in JavaScript (e.g. to avoid CORS or to keep the API key in JS), you can pass the result into the Go check via `Config.HIBPResult`:

```go
// In Go (WASM entry or wrapper), after JS has done the HIBP lookup:
cfg := passcheck.DefaultConfig()
cfg.HIBPResult = &passcheck.HIBPCheckResult{Breached: true, Count: 42}
result, _ := passcheck.CheckWithConfig(password, cfg)
```

When `HIBPResult` is non-nil, `HIBPChecker` is ignored for that check. This allows the browser to perform the k-anonymity request and pass `Breached` and `Count` into the config before calling the Go checker.

No change is required if you use `HIBPChecker` only or do not use HIBP.

### Constant-time mode

If you use `Config.ConstantTimeMode`, the set of reported issues (and their count) now matches the non-constant-time path. Previously, constant-time mode could report more dictionary issues (overlapping substrings); it now reports only maximal matches, consistent with the default mode.

---

## v1.0.0 → v1.1.0

v1.1.0 adds structured issues, policy presets, context-aware detection, and HTTP middleware. The library remains backward-compatible for most use cases.

### 1. Result.Issues is now `[]Issue` (was `[]string`)

**Before (v1.0.0):**

```go
result := passcheck.Check("password")
for _, msg := range result.Issues {
    fmt.Println(msg)
}
```

**After (v1.1.0) — option A (use new type):**

```go
result := passcheck.Check("password")
for _, iss := range result.Issues {
    fmt.Println(iss.Message)
    // Optional: branch by iss.Code (e.g. "DICT_COMMON_PASSWORD", "RULE_TOO_SHORT")
}
```

**After (v1.1.0) — option B (keep []string):**

```go
result := passcheck.Check("password")
for _, msg := range result.IssueMessages() {
    fmt.Println(msg)
}
```

`IssueMessages()` returns the same slice of message strings as before, so you can drop it in without other changes.

### 2. JSON output shape

If you serialize `Result` to JSON (e.g. for an API), the `issues` field is now an array of objects:

```json
{
  "score": 42,
  "verdict": "Weak",
  "issues": [
    { "code": "DICT_COMMON_PASSWORD", "message": "Found in common password lists", "category": "dictionary", "severity": 3 }
  ],
  "suggestions": [],
  "entropy": 28.5
}
```

If your clients expected `issues` as an array of strings, update them to use `issue.message` (or keep using `IssueMessages()` and build your own JSON).

### 3. New: Policy presets

You can replace manual config with a preset:

```go
// Before
cfg := passcheck.DefaultConfig()
cfg.MinLength = 8
cfg.RequireUpper = false
cfg.RequireLower = false
cfg.RequireDigit = false
cfg.RequireSymbol = false

// After (NIST-style)
cfg := passcheck.NISTConfig()
```

Available presets: `NISTConfig()`, `UserFriendlyConfig()`, `OWASPConfig()`, `PCIDSSConfig()`, `EnterpriseConfig()`. See [presets.go](presets.go) and the README.

### 4. New: Context-aware detection

To reject passwords that contain the username, email, or other custom words:

```go
cfg := passcheck.DefaultConfig()
cfg.ContextWords = []string{"john", "user@example.com", "company"}
result, _ := passcheck.CheckWithConfig("John123!", cfg)
// result.Issues will include a context issue if the password contains "john"
```

No change required if you do not set `ContextWords`.

### 5. New: HTTP middleware

To protect registration or password-change endpoints:

```go
import "github.com/rafaelsanzio/passcheck/middleware"

http.Handle("/register", middleware.HTTP(middleware.Config{
    MinScore:      60,
    PasswordField: "password",
}, registerHandler))
```

Optional adapters for Chi, Echo, Gin, Fiber are in the same package (build tags). See [middleware](middleware/) and [examples/middleware](examples/middleware/).

### Summary

| Change | Action |
|--------|--------|
| You iterate over `result.Issues` as strings | Use `result.IssueMessages()` or switch to `iss.Message` and optionally `iss.Code` |
| You rely on `Result` JSON with `issues` as string array | Update clients to use `issues[].message` or build response from `IssueMessages()` |
| You build config manually | Consider a preset: `NISTConfig()`, `OWASPConfig()`, etc. |
| You want to block username/email in passwords | Set `Config.ContextWords` |
| You have an HTTP registration endpoint | Add `middleware.HTTP(cfg, handler)` |

No code change is required if you only use `Check()` or `CheckWithConfig()` and do not depend on the type of `Result.Issues` (e.g. you only use `result.Score` and `result.Verdict`).

---

## Optional: Breach database (HIBP)

To check passwords against the Have I Been Pwned breach database (k-anonymity; only a 5-char hash prefix is sent), set `Config.HIBPChecker` to a client from the [hibp](hibp/) package:

```go
import (
    "github.com/rafaelsanzio/passcheck"
    "github.com/rafaelsanzio/passcheck/hibp"
)

cfg := passcheck.DefaultConfig()
cfg.HIBPChecker = hibp.NewClient()
cfg.HIBPMinOccurrences = 1
result, _ := passcheck.CheckWithConfig(password, cfg)
```

Breach findings appear as issues with `Code == passcheck.CodeHIBPBreached`. On network or API errors, the breach check is skipped. See [hibp](hibp/) and [examples/hibp](examples/hibp/).

Alternatively, you can set `Config.HIBPResult` with a pre-computed result (e.g. from a WASM/JS HIBP check) so the library does not call `HIBPChecker`; see the v1.1.0 → v1.2.0 section above.
