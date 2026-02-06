# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Expanded dictionary**: common password list grown to 953 unique entries
  (from ~100), common English word list grown to 492 entries (from ~50).
- **Custom blocklists**: `Config.CustomPasswords` and `Config.CustomWords`
  fields allow user-supplied organization-specific password and word lists
  for dictionary checks.
- **Dictionary Options API**: `dictionary.Options`, `dictionary.DefaultOptions`,
  and `dictionary.CheckWith` for fine-grained control over dictionary checks.
- **List integrity tests**: automated validation for duplicate detection,
  lowercase enforcement, sort-order verification, and minimum length compliance.
- **`go generate` validation**: `go generate ./internal/dictionary/...` runs
  list integrity tests as a pre-commit safeguard.
- **Makefile target**: `make validate-lists` to run dictionary list validation.
- **New benchmarks**: `BenchmarkCheckWith_CustomPasswords`,
  `BenchmarkCheckWith_CustomWords`, `BenchmarkCheckWith_LargeCustomList`.
- **Leet toggle**: `Config.DisableLeet` / `dictionary.Options.DisableLeet`
  to disable leetspeak normalization in dictionary checks.
- **Full API symmetry**: `dictionary` package now follows the same
  `Check / CheckWith / Options / DefaultOptions` contract as `rules`
  and `patterns`.

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
- **Dictionary checks**: common password list (~100 entries), common English
  word detection (~50 entries), leetspeak normalization for dictionary lookups.
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
