# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue.
2. Email the maintainer directly (see repository contact info).
3. Include a clear description and reproduction steps.
4. Allow reasonable time for a fix before public disclosure.

## Security Audit Checklist

The following items have been reviewed for the v1.0.0 release:

- [x] **No password logging**: the library never logs, prints, or persists
  password values. Only aggregate scores and generic descriptions are returned.
- [x] **Secure memory handling**: `CheckBytes` and `CheckBytesWithConfig` zero
  the input `[]byte` immediately after analysis using Go 1.21 `clear()`.
- [x] **Input length limits**: passwords are truncated to 1024 runes
  (`MaxPasswordLength`) before analysis to prevent algorithmic DoS.
- [x] **Bounded algorithms**: pattern detection loops are capped (`maxBlockLen`,
  `maxBlockIssues`, `maxKeyboardIssues`) to prevent quadratic complexity.
- [x] **No external dependencies**: the library uses only the Go standard
  library, minimizing supply-chain risk.
- [x] **No network calls**: the library never contacts external services.
- [x] **No file I/O**: the library never reads from or writes to the filesystem.
- [x] **Thread safety**: all exported functions are safe for concurrent use with
  no shared mutable state.
- [x] **Fuzz testing**: `FuzzCheck` and `FuzzCheckBytes` test robustness against
  random inputs.
- [x] **Configuration validation**: `Config.Validate()` rejects invalid values
  before any analysis begins.
- [x] **No panics**: all code paths return errors or handle edge cases gracefully
  (empty strings, nil slices, zero-length inputs).

## Limitations

- Go strings are immutable and garbage-collected. The runtime may retain copies
  of string data in CPU caches, swap, or core dumps. `CheckBytes` reduces but
  does not eliminate the window of exposure.
- The built-in dictionaries are intentionally small. Production deployments
  should complement with external breach databases.
- Entropy is a heuristic estimate, not a cryptographic guarantee.
