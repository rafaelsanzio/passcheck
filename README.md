# passcheck

[![CI](https://github.com/rafaelsanzio/passcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/rafaelsanzio/passcheck/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/rafaelsanzio/passcheck/branch/main/graph/badge.svg)](https://codecov.io/gh/rafaelsanzio/passcheck)
[![Go Reference](https://pkg.go.dev/badge/github.com/rafaelsanzio/passcheck.svg)](https://pkg.go.dev/github.com/rafaelsanzio/passcheck)
[![Go Report Card](https://goreportcard.com/badge/github.com/rafaelsanzio/passcheck)](https://goreportcard.com/report/github.com/rafaelsanzio/passcheck)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A comprehensive, zero-dependency Go library for password strength checking.

Passcheck evaluates passwords against multiple criteria — basic rules, pattern
detection, dictionary checks, and entropy calculation — returning an actionable
result with a score, verdict, and specific feedback.

## Features

- **Score & Verdict** — 0-100 score mapped to human-readable strength labels
- **Pattern Detection** — Keyboard walks, sequences, repeated blocks, leetspeak
- **Dictionary Checks** — ~950 common passwords, ~490 common words, leet variants
- **Custom Blocklists** — Add organization-specific passwords and words via config
- **Entropy Calculation** — Shannon entropy based on character-set diversity
- **Configurable Rules** — Adjust minimum length, character requirements, thresholds
- **Actionable Feedback** — Prioritized issues and positive suggestions
- **Secure Memory** — `CheckBytes` zeros input after analysis
- **CLI Tool** — Colored output, JSON mode, verbose mode
- **Zero Dependencies** — Only the Go standard library

## Installation

### As a Library

```bash
go get github.com/rafaelsanzio/passcheck
```

### As a CLI Tool

```bash
go install github.com/rafaelsanzio/passcheck/cmd/passcheck@latest
```

Or build from source:

```bash
git clone https://github.com/rafaelsanzio/passcheck.git
cd passcheck
make build       # builds to bin/passcheck
make install     # installs to $GOPATH/bin
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

    for _, issue := range result.Issues {
        fmt.Printf("  - %s\n", issue)
    }
    for _, s := range result.Suggestions {
        fmt.Printf("  + %s\n", s)
    }
}
```

## CLI Usage

```bash
# Basic check
passcheck "MyP@ssw0rd123!"

# JSON output
passcheck "qwerty" --json

# Verbose mode (all issues, extra details)
passcheck "password" --verbose

# Custom minimum length
passcheck "aB3!xY" --min-length=6

# Disable colors
passcheck "test" --no-color

# Password starting with a dash
passcheck -- "-mypassword"

# Show help
passcheck --help
```

### CLI Flags

| Flag             | Short | Description                                    |
| ---------------- | ----- | ---------------------------------------------- |
| `--json`         |       | Output as JSON                                 |
| `--verbose`      | `-v`  | Show all issues and extra details              |
| `--no-color`     |       | Disable ANSI colors                            |
| `--min-length=N` |       | Override minimum password length (default: 12) |
| `--version`      |       | Show version                                   |
| `--help`         | `-h`  | Show help                                      |

The `NO_COLOR` environment variable is also respected.

### Sample Output

```
Score:   [██████████] 100/100
Verdict: Very Strong
Entropy: 131.1 bits

Strengths:
  + Good length (20 characters)
  + Good character diversity (4 of 4 character types)
  + No common patterns detected
  + Not found in common password lists
  + Good entropy (131 bits)
```

## API Reference

### Core Functions

```go
// Check with default configuration.
func Check(password string) Result

// Check with custom configuration.
func CheckWithConfig(password string, cfg Config) (Result, error)

// Check from a []byte — input is zeroed after analysis.
func CheckBytes(password []byte) Result

// Check from a []byte with custom configuration.
func CheckBytesWithConfig(password []byte, cfg Config) (Result, error)
```

### Result

```go
type Result struct {
    Score       int      // 0 (weakest) to 100 (strongest)
    Verdict     string   // "Very Weak", "Weak", "Okay", "Strong", "Very Strong"
    Issues      []string // Prioritized, deduplicated problems
    Suggestions []string // Positive feedback about strengths
    Entropy     float64  // Estimated entropy in bits
}
```

### Verdicts

| Score Range | Verdict     |
| ----------- | ----------- |
| 0–20        | Very Weak   |
| 21–40       | Weak        |
| 41–60       | Okay        |
| 61–80       | Strong      |
| 81–100      | Very Strong |

## Configuration

Use `DefaultConfig()` and override fields as needed:

```go
cfg := passcheck.DefaultConfig()
cfg.MinLength = 8          // allow shorter passwords
cfg.RequireSymbol = false  // don't require symbols
cfg.MaxRepeats = 4         // allow up to 3 consecutive identical chars
cfg.PatternMinLength = 3   // stricter pattern detection
cfg.MaxIssues = 10         // show more issues

result, err := passcheck.CheckWithConfig("mypassword", cfg)
if err != nil {
    log.Fatal(err) // invalid config
}
```

### Config Fields

| Field              | Type   | Default | Description                                |
| ------------------ | ------ | ------- | ------------------------------------------ |
| `MinLength`        | `int`  | 12      | Minimum runes required                     |
| `RequireUpper`     | `bool` | true    | Require uppercase letter                   |
| `RequireLower`     | `bool` | true    | Require lowercase letter                   |
| `RequireDigit`     | `bool` | true    | Require numeric digit                      |
| `RequireSymbol`    | `bool` | true    | Require symbol character                   |
| `MaxRepeats`       | `int`  | 3       | Max consecutive identical characters       |
| `PatternMinLength` | `int`  | 4       | Min length for keyboard/sequence detection |
| `MaxIssues`        | `int`  | 5       | Max issues returned (0 = no limit)         |
| `CustomPasswords`  | `[]string` | nil | Additional passwords to block (case-insensitive) |
| `CustomWords`      | `[]string` | nil | Additional words to detect as substrings   |
| `DisableLeet`      | `bool` | false   | Disable leetspeak normalization in dictionary checks |

### Custom Blocklists

Add organization-specific passwords and words:

```go
cfg := passcheck.DefaultConfig()
cfg.CustomPasswords = []string{"CompanyName2024", "InternalProject"}
cfg.CustomWords = []string{"acmecorp", "projectx"}

result, _ := passcheck.CheckWithConfig("iloveacmecorp99!", cfg)
// "acmecorp" will be detected as a common word
```

### Disabling Leet Normalization

By default, passwords like `p@$$w0rd` are normalized to `password` before
dictionary lookups. To disable this behavior:

```go
cfg := passcheck.DefaultConfig()
cfg.DisableLeet = true
// "@dm1n" will NOT be flagged as a variant of "admin"
```

### Policy Presets

Use standard-based presets instead of building config from scratch:

| Preset | Use case | Min length | Complexity |
|--------|----------|------------|------------|
| `NISTConfig()` | NIST SP 800-63B (length over composition) | 8 | None |
| `UserFriendlyConfig()` | Consumer apps, low friction | 10 | Lower + digit |
| `OWASPConfig()` | Web apps, SaaS (OWASP recommendations) | 10 | Upper + lower + digit |
| `PCIDSSConfig()` | PCI-DSS v4.0 (payment card systems) | 12 | Full |
| `EnterpriseConfig()` | High-security / enterprise | 14 | Full, strict |

```go
// NIST: length and dictionary only, no composition rules
cfg := passcheck.NISTConfig()
result, _ := passcheck.CheckWithConfig("correct-horse-battery-staple", cfg)

// PCI-DSS: strict complexity for payment systems
cfg := passcheck.PCIDSSConfig()
result, _ := passcheck.CheckWithConfig("MyC0mpl3x!P@ss2024", cfg)
```

Each preset is documented in godoc with standard references (NIST SP 800-63B, PCI-DSS 8.3.6, OWASP Authentication Cheat Sheet). See [presets.go](presets.go).

**Migrating from DefaultConfig():** If you currently use `DefaultConfig()` and override a few fields, you can often replace that with a preset and then tweak:

- Need shorter passwords and no composition rules? Use `NISTConfig()`.
- Need same strictness as today? `DefaultConfig()` is already close to `PCIDSSConfig()` (both min 12, full complexity). Switch to `passcheck.PCIDSSConfig()` for a named, standard-based config.
- Need slightly looser for better UX? Use `OWASPConfig()` (symbols optional) or `UserFriendlyConfig()` (min 10, fewer requirements).

You can still override after calling a preset, e.g. `cfg := passcheck.NISTConfig(); cfg.CustomPasswords = myList`.

### Validation

`Config.Validate()` checks for invalid values:

- `MinLength >= 1`
- `MaxRepeats >= 2`
- `PatternMinLength >= 3`
- `MaxIssues >= 0`

`CheckWithConfig` calls `Validate()` automatically and returns an error
for invalid configurations.

## Security Considerations

**Memory handling:** Go strings are immutable and garbage-collected — the library
cannot zero them after use. For applications that receive passwords as `[]byte`
(HTTP request bodies, terminal reads), use `CheckBytes` or `CheckBytesWithConfig`
which zero the input slice immediately after analysis.

**No logging:** The library never logs, prints, or persists passwords. Results
contain only aggregate scores and generic issue descriptions.

**Input limits:** A maximum of 1024 runes is analysed per password to prevent
denial-of-service through algorithmic complexity. Inputs beyond this are silently
truncated.

**Limitations:**

- The Go runtime may retain copies of string data in CPU caches, swap, or core
  dumps. `CheckBytes` reduces — but does not eliminate — the window of exposure.
- The built-in dictionary contains ~950 common passwords and ~490 common
  words. Production deployments may want to complement this with
  external breach databases (e.g. Have I Been Pwned).
- Entropy is estimated from character-set diversity and length, not from the
  full distribution of possible passwords.

## Architecture

```
passcheck/
├── passcheck.go        # Public API: Check, CheckWithConfig, CheckBytes
├── config.go           # Config struct, DefaultConfig, Validate
├── presets.go          # NIST, PCI-DSS, OWASP, Enterprise, UserFriendly presets
├── internal/
│   ├── rules/          # Basic rules: length, charsets, whitespace, repeats
│   ├── patterns/       # Pattern detection: keyboard, sequence, blocks, substitution
│   ├── dictionary/     # Dictionary checks: common passwords, common words
│   ├── entropy/        # Shannon entropy calculation
│   ├── scoring/        # Weighted scoring algorithm
│   ├── feedback/       # Issue dedup, priority sort, positive feedback
│   ├── leet/           # Shared leetspeak normalisation utilities
│   └── safemem/        # Secure memory zeroing
├── cmd/passcheck/      # CLI tool
├── examples/           # Usage examples
└── Makefile            # Build, test, cross-compile
```

Each internal package follows the same pattern:

- `Check(password) []string` — default options
- `CheckWith(password, opts) []string` — custom options
- `DefaultOptions()` — recommended defaults

The scoring formula combines entropy, weighted penalties (per category),
and bonuses (length + character-set diversity) into a 0-100 score.

## Performance

Benchmarks run on Apple Silicon (M-series), Go 1.21+. Results vary by
hardware but relative magnitudes are representative.

| Input | Time | Allocs | Bytes |
|-------|------|--------|-------|
| Empty password | ~420 ns | 7 | 184 B |
| Short (6 chars) | ~1.0 µs | 20 | 923 B |
| Common password | ~4.1 µs | 38 | 1.6 KB |
| Medium (12 chars) | ~12 µs | 52 | 872 B |
| Strong (20 chars) | ~23 µs | 95 | 1.3 KB |
| Long (100 chars) | ~137 µs | 598 | 10 KB |
| Very long (1000 chars) | ~1.4 ms | 5999 | 89 KB |
| Unicode (20 chars) | ~26 µs | 58 | 1.2 KB |

### Performance characteristics

- **Typical passwords (8–20 chars):** sub-25 µs with minimal allocations.
- **Long passwords:** linear scaling up to `MaxPasswordLength` (1024 runes),
  with pattern detection capped to prevent quadratic blowup.
- **Memory:** `CheckBytes` adds only 48 bytes overhead for the byte-to-string
  conversion plus zeroing; the check itself allocates the same as `Check`.
- **Thread safety:** all functions are safe for concurrent use — no shared
  mutable state.

Run benchmarks yourself:

```bash
make bench
# or
go test ./... -bench=. -benchmem -count=3 -run='^$' -timeout=120s
```

## Development

```bash
make test       # run all tests
make cover      # coverage report
make bench      # run benchmarks
make lint       # go vet
make lint-ci    # golangci-lint (comprehensive)
make build      # build CLI
make cross      # cross-compile for all platforms
make clean      # remove build artifacts
make help       # show all targets
```

### CI/CD

Every push and pull request triggers a GitHub Actions pipeline that:

- Runs `go vet` and [`golangci-lint`](https://golangci-lint.run/) with a
  curated linter set (see [`.golangci.yml`](.golangci.yml))
- Runs `go test -race` on a Go version matrix (1.21, 1.22, latest) across
  Linux, macOS, and Windows
- Uploads coverage to [Codecov](https://codecov.io/gh/rafaelsanzio/passcheck)
- Builds the CLI and all examples

A separate nightly workflow runs fuzz tests (`FuzzCheck`, `FuzzCheckBytes`)
for 60 seconds each and uploads crash artifacts on failure.

### Test Coverage

The project maintains **97%+ statement coverage** across all library packages,
including fuzz tests, benchmarks, and integration tests.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for new functionality
4. Ensure all tests pass (`make test`)
5. Ensure code passes `go vet` (`make lint`)
6. Commit with a clear message
7. Open a pull request

Please follow the existing code style: Go conventions, table-driven tests,
comprehensive doc comments.

## License

This project is available under the MIT License. See [LICENSE](LICENSE) for details.
