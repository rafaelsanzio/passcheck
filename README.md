# passcheck

[![CI](https://github.com/rafaelsanzio/passcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/rafaelsanzio/passcheck/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/rafaelsanzio/passcheck/graph/badge.svg)](https://app.codecov.io/gh/rafaelsanzio/passcheck)
[![Go Reference](https://pkg.go.dev/badge/github.com/rafaelsanzio/passcheck.svg)](https://pkg.go.dev/github.com/rafaelsanzio/passcheck)
[![Go Report Card](https://goreportcard.com/badge/github.com/rafaelsanzio/passcheck)](https://goreportcard.com/report/github.com/rafaelsanzio/passcheck)
[![Go Version](https://img.shields.io/github/go-mod/go-version/rafaelsanzio/passcheck)](go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A comprehensive, zero-dependency Go library for password strength checking.

Passcheck evaluates passwords against multiple criteria — basic rules, pattern detection, dictionary checks, and entropy calculation — returning a scored result with a verdict and structured, actionable feedback.

## Features

- **Score & Verdict** — 0-100 score mapped to `Very Weak` / `Weak` / `Okay` / `Strong` / `Very Strong`
- **Structured Issues** — typed `Issue` (Code, Message, Category, Severity) for programmatic handling
- **Pattern Detection** — keyboard walks, sequences, repeated blocks, leetspeak
- **Dictionary Checks** — ~950 common passwords, ~490 common words, leet variants
- **Context-Aware Detection** — reject passwords containing username, email, or custom terms
- **Policy Presets** — NIST, PCI-DSS, OWASP, Enterprise, UserFriendly in one call
- **Breach Database (HIBP)** — optional [Have I Been Pwned](https://haveibeenpwned.com/) integration via k-anonymity
- **HTTP Middleware** — drop-in for net/http; Gin, Echo, Fiber adapters as independent submodules
- **Entropy Modes** — Simple, Advanced (pattern-aware), Pattern-Aware (Markov-chain)
- **Passphrase Support** — word-based entropy with diceware model
- **Configurable Weights** — customize penalty multipliers and entropy weight
- **Real-Time Feedback** — `CheckIncremental` with delta for live strength meters
- **Secure Memory** — `CheckBytes` zeros input after analysis
- **CLI Tool** — colored output, JSON mode, verbose mode
- **WebAssembly** — [WASM build](wasm/README.md) for client-side validation; includes a [TypeScript/Vite web app](wasm/web/README.md)
- **Zero Dependencies** — root library uses stdlib only

For upgrade instructions see [MIGRATION.md](MIGRATION.md).

## Installation

```bash
# Library
go get github.com/rafaelsanzio/passcheck

# CLI
go install github.com/rafaelsanzio/passcheck/cmd/passcheck@latest
```

Or build from source:

```bash
git clone https://github.com/rafaelsanzio/passcheck.git
cd passcheck
make build       # builds to bin/passcheck
make install     # installs to $GOPATH/bin
make test        # run tests
make wasm        # build WASM and copy to wasm/web/public/
```

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/rafaelsanzio/passcheck"
)

func main() {
    result := passcheck.Check("MyP@ssw0rd123!")

    fmt.Printf("Score:   %d/100\n", result.Score)
    fmt.Printf("Verdict: %s\n", result.Verdict)
    fmt.Printf("Entropy: %.1f bits\n", result.Entropy)

    for _, iss := range result.Issues {
        fmt.Printf("  - %s\n", iss.Message)
    }
    for _, s := range result.Suggestions {
        fmt.Printf("  + %s\n", s)
    }
}
```

## CLI Usage

```bash
passcheck "MyP@ssw0rd123!"          # basic check
passcheck "qwerty" --json           # JSON output
passcheck "password" --verbose      # all issues and extra details
passcheck "aB3!xY" --min-length=6   # custom minimum length
passcheck -- "-mypassword"          # password starting with a dash
passcheck --help
```

| Flag             | Short | Description                                    |
| ---------------- | ----- | ---------------------------------------------- |
| `--json`         |       | Output as JSON                                 |
| `--verbose`      | `-v`  | Show all issues and extra details              |
| `--no-color`     |       | Disable ANSI colors (`NO_COLOR` env also works)|
| `--min-length=N` |       | Override minimum password length (default: 12) |
| `--version`      |       | Show version                                   |
| `--help`         | `-h`  | Show help                                      |

## API Reference

### Core Functions

```go
func Check(password string) Result
func CheckWithConfig(password string, cfg Config) (Result, error)
func CheckBytes(password []byte) Result
func CheckBytesWithConfig(password []byte, cfg Config) (Result, error)
func CheckIncremental(password string, previous *Result) Result
func CheckIncrementalWithConfig(password string, previous *Result, cfg Config) (Result, IncrementalDelta, error)
```

### Result and Issue

```go
type Result struct {
    Score       int      // 0–100
    Verdict     string   // "Very Weak" … "Very Strong"
    MeetsPolicy bool     // all configured minimums satisfied
    Issues      []Issue  // prioritized, deduplicated problems
    Suggestions []string // positive feedback
    Entropy     float64  // estimated bits
}

type Issue struct {
    Code     string // e.g. "RULE_TOO_SHORT", "DICT_COMMON_PASSWORD", "HIBP_BREACHED"
    Message  string
    Category string // "rule", "pattern", "dictionary", "context", "breach"
    Severity int    // 1 (low) – 3 (high)
}

type IncrementalDelta struct {
    ScoreChanged       bool
    IssuesChanged      bool
    SuggestionsChanged bool
}
```

Use `result.IssueMessages()` for a `[]string` of messages (backward compatibility).

### Verdicts

| Score | Verdict     |
| ----- | ----------- |
| 0–20  | Very Weak   |
| 21–40 | Weak        |
| 41–60 | Okay        |
| 61–80 | Strong      |
| 81–100| Very Strong |

## Configuration

```go
cfg := passcheck.DefaultConfig()
cfg.MinLength = 8
cfg.RequireSymbol = false
cfg.MaxRepeats = 4

result, err := passcheck.CheckWithConfig("mypassword", cfg)
```

Key fields (see [pkg.go.dev](https://pkg.go.dev/github.com/rafaelsanzio/passcheck#Config) for the full reference):

| Field                | Default  | Description                                              |
| -------------------- | -------- | -------------------------------------------------------- |
| `MinLength`          | 12       | Minimum runes required                                   |
| `RequireUpper`       | true     | Require uppercase letter                                 |
| `RequireLower`       | true     | Require lowercase letter                                 |
| `RequireDigit`       | true     | Require numeric digit                                    |
| `RequireSymbol`      | true     | Require symbol character                                 |
| `MaxRepeats`         | 3        | Max consecutive identical characters                     |
| `ContextWords`       | nil      | User-specific terms (username, email) to reject          |
| `HIBPChecker`        | nil      | Optional breach check; see [hibp/](hibp/)                |
| `PassphraseMode`     | false    | Word-based entropy and scoring for passphrases           |
| `EntropyMode`        | "simple" | `"simple"`, `"advanced"`, or `"pattern-aware"`           |
| `PenaltyWeights`     | nil      | Custom penalty multipliers; see [docs/WEIGHT_TUNING.md](docs/WEIGHT_TUNING.md) |
| `RedactSensitive`    | false    | Mask password substrings in issue messages               |

### Policy Presets

| Preset                 | Use case                             | Min length | Complexity            |
| ---------------------- | ------------------------------------ | ---------- | --------------------- |
| `NISTConfig()`         | NIST SP 800-63B (length over rules)  | 8          | None                  |
| `UserFriendlyConfig()` | Consumer apps, low friction          | 10         | Lower + digit         |
| `OWASPConfig()`        | Web apps, SaaS                       | 10         | Upper + lower + digit |
| `PCIDSSConfig()`       | PCI-DSS v4.0                         | 12         | Full                  |
| `EnterpriseConfig()`   | High-security / enterprise           | 14         | Full, strict          |

```go
cfg := passcheck.NISTConfig()
result, _ := passcheck.CheckWithConfig("correct-horse-battery-staple", cfg)
```

Presets can be further customized: `cfg := passcheck.NISTConfig(); cfg.CustomPasswords = myList`.

### Custom Blocklists & Context-Aware Detection

```go
cfg := passcheck.DefaultConfig()
cfg.CustomPasswords = []string{"CompanyName2024", "InternalProject"}
cfg.CustomWords     = []string{"acmecorp", "projectx"}
cfg.ContextWords    = []string{"john", "john.doe@acme.com"} // username / email
```

`ContextWords` matching is case-insensitive, supports substrings and leetspeak variants. Email addresses are split into local and domain parts. Words shorter than 3 characters are ignored.

### Breach Database (HIBP)

Only the first 5 characters of the SHA-1 hash are sent to the API — the full password is never transmitted (k-anonymity).

```go
import (
    "github.com/rafaelsanzio/passcheck"
    "github.com/rafaelsanzio/passcheck/hibp"
)

cfg := passcheck.DefaultConfig()
client := hibp.NewClient()
client.Cache = hibp.NewMemoryCacheWithTTL(256, hibp.DefaultCacheTTL)
cfg.HIBPChecker = client

result, _ := passcheck.CheckWithConfig(password, cfg)
```

On network errors the breach check is skipped and the rest of the result is returned (graceful degradation). For WASM builds, pass a pre-computed result via `Config.HIBPResult`. See [examples/hibp](examples/hibp/) and [hibp/](hibp/).

### Passphrase Mode

```go
cfg := passcheck.DefaultConfig()
cfg.PassphraseMode = true
cfg.MinWords     = 4     // minimum distinct words
cfg.WordDictSize = 7776  // diceware dictionary size

result, _ := passcheck.CheckWithConfig("correct-horse-battery-staple", cfg)
// word-based entropy: 4 × log₂(7776) ≈ 51 bits
```

### Advanced Entropy & Scoring Weights

```go
cfg.EntropyMode = passcheck.EntropyModeAdvanced      // pattern-aware reduction
cfg.EntropyMode = passcheck.EntropyModePatternAware  // + Markov-chain analysis

cfg.PenaltyWeights = &passcheck.PenaltyWeights{
    DictionaryMatch: 2.0,
    PatternMatch:    1.5,
    EntropyWeight:   0.8,
}
```

See [docs/WEIGHT_TUNING.md](docs/WEIGHT_TUNING.md) for tuning guidance.

### Real-Time Feedback

```go
var last *passcheck.Result
func onPasswordChange(password string) {
    result, delta, _ := passcheck.CheckIncrementalWithConfig(password, last, cfg)
    if delta.ScoreChanged || delta.IssuesChanged {
        updateMeter(result.Score, result.Issues)
    }
    last = &result
}
```

Debounce calls on every keystroke (100–300 ms) to limit CPU usage.

### WebAssembly (client-side)

Build with `make wasm`, then run `make serve-wasm` to start the TypeScript/Vite dev server. The [WASM build](wasm/README.md) exposes `passcheckCheck`, `passcheckCheckWithConfig`, and incremental variants as global JS functions. A [modern web app](wasm/web/README.md) with dark mode, Web Workers, and full configuration UI is included.

### HTTP Middleware

```go
import "github.com/rafaelsanzio/passcheck/middleware"

mux.Handle("/register", middleware.HTTP(middleware.Config{
    MinScore:      60,
    PasswordField: "password",
}, registerHandler))
```

Framework adapters (independent submodules — add only what you need):

```bash
go get github.com/rafaelsanzio/passcheck/middleware/gin
go get github.com/rafaelsanzio/passcheck/middleware/echo
go get github.com/rafaelsanzio/passcheck/middleware/fiber
```

```go
// Gin
r.POST("/register", passcheckgin.Gin(middleware.Config{MinScore: 60}), handler)

// Echo
e.POST("/register", handler, passcheckecho.Echo(middleware.Config{MinScore: 60}))

// Fiber
app.Post("/register", passcheckfiber.Fiber(middleware.Config{MinScore: 60}), handler)
```

Chi uses the standard `middleware.HTTP` wrapper — no extra dependency needed. See [examples/middleware](examples/middleware/).

## Security Best Practices

1. **Do not log `Result.Issues` raw** — messages may contain password substrings. Log only `Code`, or set `Config.RedactSensitive = true`.
2. **Prefer `CheckBytes`** — use when passwords are available as `[]byte`; the buffer is zeroed immediately after analysis.
3. **Enable `ConstantTimeMode`** — mitigates timing side channels in dictionary lookups for high-assurance scenarios.
4. **Run security tooling** — `make security` runs `govulncheck` and `gosec` locally.

## Architecture

```
passcheck/
├── passcheck.go        # Public API: Check, CheckIncremental, CheckWithConfig, CheckBytes
├── config.go           # Config struct, DefaultConfig, Validate
├── presets.go          # NIST, PCI-DSS, OWASP, Enterprise, UserFriendly presets
├── hibp/               # Optional HIBP breach API client (k-anonymity)
├── middleware/         # HTTP middleware (net/http, Chi); gin/echo/fiber as submodules
├── internal/
│   ├── rules/          # Basic rules: length, charsets, whitespace, repeats
│   ├── patterns/       # Pattern detection: keyboard, sequence, blocks, substitution, dates
│   ├── dictionary/     # Dictionary checks: common passwords, common words
│   ├── entropy/        # Entropy calculation (simple, advanced, pattern-aware modes)
│   ├── passphrase/     # Passphrase detection and word-based entropy
│   ├── scoring/        # Weighted scoring algorithm
│   ├── feedback/       # Issue dedup, priority sort, positive feedback
│   ├── context/        # Context-aware detection
│   ├── hibpcheck/      # HIBP breach result integration
│   ├── issue/          # Shared issue type definitions and constants
│   ├── leet/           # Leetspeak normalisation utilities
│   └── safemem/        # Secure memory zeroing and constant-time comparisons
├── cmd/passcheck/      # CLI tool
├── examples/           # Usage examples
└── Makefile            # Build, test, cross-compile
```

## Performance

Benchmarks on Apple Silicon (M-series), Go 1.24+:

| Input                  | Time    | Allocs | Bytes  |
| ---------------------- | ------- | ------ | ------ |
| Empty password         | ~420 ns | 7      | 184 B  |
| Short (6 chars)        | ~1.0 µs | 20     | 923 B  |
| Common password        | ~4.1 µs | 38     | 1.6 KB |
| Medium (12 chars)      | ~12 µs  | 52     | 872 B  |
| Strong (20 chars)      | ~23 µs  | 95     | 1.3 KB |
| Long (100 chars)       | ~137 µs | 598    | 10 KB  |
| Very long (1000 chars) | ~1.4 ms | 5999   | 89 KB  |

All functions are safe for concurrent use. Run `make bench` to benchmark locally.

## Development

```bash
make test       # run tests (core module)
make test-all   # run tests for core and middleware submodules
make cover      # coverage report
make bench      # run benchmarks
make lint-ci    # golangci-lint (comprehensive)
make build      # build CLI
make wasm       # build WASM binary
make cross      # cross-compile for all platforms
make clean      # remove build artifacts
make help       # show all targets
```

CI runs lint, `go test -race`, `govulncheck`, and coverage upload on every push/PR. A [WASM workflow](.github/workflows/wasm.yml) reports bundle sizes; a nightly [Fuzz workflow](.github/workflows/fuzz.yml) runs fuzz targets.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for new functionality
4. Ensure tests pass (`make test`) and lint passes (`make lint-ci`)
5. Open a pull request

Please follow existing code style: Go conventions, table-driven tests, godoc comments.

## License

This project is available under the MIT License. See [LICENSE](LICENSE) for details.
