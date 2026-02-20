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

For an automated and manual **security assessment** (tooling, findings, and mitigations), see [docs/SECURITY_ASSESSMENT.md](docs/SECURITY_ASSESSMENT.md). Run `make check` (which includes `make security`) for vulnerability and security lint checks.

## Security Audit Checklist

The following items have been reviewed for the v1.0.0 release:

- [x] **No password logging**: the library never logs, prints, or persists
  password values. Results contain only aggregate scores and generic
  descriptions. Substrings can be redacted using `Config.RedactSensitive = true`.
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
- [x] **Timing attack mitigation (optional)**: `ConstantTimeMode` and
  `MinExecutionTimeMs` provide constant-time dictionary lookups and
  execution-time padding when enabled; see [Timing attack protection](#timing-attack-protection-optional).
- [x] **WebAssembly (browser) build**: The [wasm](wasm/README.md) build runs entirely in the
  browser; the password is never sent to the server by this library. Optional HIBP
  (when enabled via config) calls the HIBP API from the browser (k-anonymity); CORS may block it in some environments.

## Timing attack protection (optional)

When handling passwords in high-assurance or threat models where an attacker
can measure response time (e.g. remote timing), enable timing-attack mitigations:

1. **Constant-time mode**  
   Set `Config.ConstantTimeMode = true`. Dictionary lookups then use
   constant-time string comparison and substring checks so that execution time
   does not depend on whether the password matched a blocklist entry or where it
   matched. This is slower than normal lookups (linear scan over lists instead
   of map lookups and short-circuit substring search).

2. **Minimum execution time**  
   Set `Config.MinExecutionTimeMs` (e.g. 10) while `ConstantTimeMode` is true.
   The library sleeps for the remaining time after the check so that total
   response duration does not leak how much work was done. Use a value that
   covers the worst-case check time on your hardware.

**Guarantees and limitations:**

- Constant-time comparison and contains are implemented using `crypto/subtle`
  and fixed iteration counts so that timing does not depend on length or
  content of the secret.
- Statistical timing tests (two no-match runs) are used in tests to verify
  that we do not short-circuit (p ≥ 0.01).
- Performance overhead when `ConstantTimeMode` is true is design-bound
  (linear scan over password and word lists); target is &lt;20% for typical
  inputs when no minimum execution time padding is used. Use the
  `BenchmarkCheckWithConfig_*` benchmarks to measure on your system.
- Minimum execution time padding is best-effort; scheduling and other
  processes can still cause variance.

## Limitations

- The WebAssembly build can optionally use HIBP when `config.useHibp` is set; the request runs in the browser and may be blocked by CORS. For guaranteed breach checking, use the server-side API.
- Go strings are immutable and garbage-collected. The runtime may retain copies
  of string data in CPU caches, swap, or core dumps. `CheckBytes` reduces but
  does not eliminate the window of exposure.
- The built-in dictionaries are intentionally small. Production deployments
  should complement with external breach databases.
- Entropy is a heuristic estimate, not a cryptographic guarantee.
