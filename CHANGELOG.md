# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - TBD

### Added

- **Structured issues**: `Result.Issues` is now `[]Issue` (Code, Message, Category, Severity). Use `Result.IssueMessages()` for a `[]string` of messages. Issue codes are stable (e.g. `RULE_TOO_SHORT`, `DICT_COMMON_PASSWORD`) for programmatic handling.
- **Policy presets**: `NISTConfig()`, `UserFriendlyConfig()`, `OWASPConfig()`, `PCIDSSConfig()`, `EnterpriseConfig()` for standard-based configuration. See [presets.go](presets.go) and [MIGRATION.md](MIGRATION.md).
- **Context-aware detection**: `Config.ContextWords` to reject passwords containing username, email, or custom terms. Matching is case-insensitive and supports substrings and leetspeak variants.
- **HTTP middleware**: [middleware](middleware/) package for net/http with optional Chi, Echo, Gin, Fiber adapters (build tags). Zero extra dependencies for standard library usage. See [examples/middleware](examples/middleware/).
- **Examples**: [examples/context](examples/context/) (context-aware), [examples/presets](examples/presets/) (policy presets), [examples/middleware](examples/middleware/) (HTTP middleware).

### Changed

- `Result.Issues` type changed from `[]string` to `[]Issue`. Use `result.IssueMessages()` for backward-compatible `[]string` access.

[1.1.0]: https://github.com/rafaelsanzio/passcheck/compare/v1.0.0...v1.1.0

## [1.0.0] - 2026-02-06

### Added

- **Core API**: `Check`, `CheckWithConfig`, `CheckBytes`, `CheckBytesWithConfig`
  functions for evaluating password strength.
- **Result struct**: score (0–100), verdict, issues, suggestions, entropy.
- **Configurable rules**: minimum length, character set requirements (upper,
  lower, digit, symbol), maximum consecutive repeats — all adjustable via
  `Config` struct.
- **Pattern detection**: keyboard walks (QWERTY/AZERTY/Dvorak), arithmetic
  sequences, repeated substring blocks, leetspeak substitutions.
- **Dictionary checks**: common password list (~950 entries), common English
  word detection (~490 entries), leetspeak normalization for dictionary lookups.
- **Custom blocklists**: `Config.CustomPasswords` and `Config.CustomWords`
  fields allow user-supplied organization-specific password and word lists
  for dictionary checks.
- **Dictionary Options API**: `dictionary.Options`, `dictionary.DefaultOptions`,
  and `dictionary.CheckWith` for fine-grained control over dictionary checks.
- **Leet toggle**: `Config.DisableLeet` / `dictionary.Options.DisableLeet`
  to disable leetspeak normalization in dictionary checks.
- **List integrity tests**: automated validation for duplicate detection,
  lowercase enforcement, sort-order verification, and minimum length compliance.
- **`go generate` validation**: `go generate ./internal/dictionary/...` runs
  list integrity tests as a pre-commit safeguard.
- **Makefile target**: `make validate-lists` to run dictionary list validation.
- **Entropy calculation**: Shannon entropy based on character-set diversity and
  password length.
- **Weighted scoring**: base score from entropy, bonuses for length and charset
  diversity, penalties weighted by issue category (rules, patterns, dictionary).
- **Feedback engine**: issue deduplication, severity-based priority sorting,
  configurable issue limit, positive feedback generation for strong passwords.
- **Secure memory handling**: `CheckBytes` and `CheckBytesWithConfig` accept
  `[]byte` input and zero it immediately after analysis using Go 1.21 `clear()`.
- **DoS prevention**: maximum password length (1024 runes) enforced via silent
  truncation.
- **CLI tool** (`cmd/passcheck`): colored output, JSON mode, verbose mode,
  custom `--min-length`, `--no-color` flag and `NO_COLOR` environment variable.
- **Cross-compilation**: Makefile with targets for Linux, macOS, and Windows
  (amd64 + arm64).
- **Comprehensive testing**: 98%+ statement coverage, table-driven tests, fuzz
  tests, benchmarks across all packages.
- **Documentation**: README with API reference, configuration guide, security
  considerations, architecture overview, performance benchmarks, and usage
  examples.
- **Examples**: standalone programs for basic usage, custom configuration, and
  HTTP web server integration.
- **Go testable examples**: verified `Example*` functions for `go doc` output.

### Security

- Passwords are never logged, printed, or persisted by the library.
- `CheckBytes` / `CheckBytesWithConfig` zero sensitive input after use.
- Input length capped at 1024 runes to prevent algorithmic DoS.
- Pattern detection loops are bounded to prevent quadratic complexity.

[Unreleased]: https://github.com/rafaelsanzio/passcheck/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/rafaelsanzio/passcheck/releases/tag/v1.0.0
