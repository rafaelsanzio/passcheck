package passcheck

import "fmt"

// HIBPCheckResult is a pre-computed result from an HIBP (Have I Been Pwned) lookup.
// When Config.HIBPResult is set, the library uses it instead of calling HIBPChecker.
type HIBPCheckResult struct {
	Breached bool
	Count    int
}

// Config holds configuration options for password strength checking.
//
// Use [DefaultConfig] to obtain a Config with recommended defaults, then
// override individual fields:
//
//	cfg := passcheck.DefaultConfig()
//	cfg.MinLength = 8
//	cfg.RequireSymbol = false
//	result, err := passcheck.CheckWithConfig("mypassword", cfg)
type Config struct {
	// MinLength is the minimum number of runes required (default: 12).
	MinLength int

	// RequireUpper requires at least one uppercase letter (default: true).
	RequireUpper bool

	// RequireLower requires at least one lowercase letter (default: true).
	RequireLower bool

	// RequireDigit requires at least one numeric digit (default: true).
	RequireDigit bool

	// RequireSymbol requires at least one symbol character (default: true).
	RequireSymbol bool

	// MaxRepeats is the maximum number of consecutive identical characters
	// allowed before an issue is reported (default: 3).
	MaxRepeats int

	// PatternMinLength is the minimum length for keyboard and sequence
	// pattern detection (default: 4).
	PatternMinLength int

	// MaxIssues is the maximum number of issues returned in the result.
	// Set to 0 for no limit (default: 5).
	MaxIssues int

	// CustomPasswords is an optional list of additional passwords to check
	// against during dictionary checks. Entries are matched case-insensitively.
	// Nil or empty means use only the built-in common password list.
	CustomPasswords []string

	// CustomWords is an optional list of additional words to detect as
	// substrings during dictionary checks. Entries are matched
	// case-insensitively. Words shorter than 4 characters are ignored.
	// Nil or empty means use only the built-in common word list.
	CustomWords []string

	// ContextWords is an optional list of user-specific terms to detect
	// in passwords (e.g., username, email, company name). Entries are
	// matched case-insensitively and checked for exact matches, substrings,
	// and leetspeak variants. Words shorter than 3 characters are ignored.
	// Email addresses are automatically parsed to extract individual components.
	// Nil or empty means no context-aware checking is performed.
	ContextWords []string

	// DisableLeet disables leetspeak normalization during dictionary
	// checks. When true, substitutions like @ → a, 0 → o, $ → s are
	// not applied, and only the plain password is checked against
	// dictionaries. Default: false (leet normalization enabled).
	DisableLeet bool

	// HIBPChecker is an optional checker for the Have I Been Pwned (HIBP)
	// breach database. When set, the password is checked via k-anonymity
	// (only a 5-character prefix of its SHA-1 hash is sent). If the
	// password is found and the count meets HIBPMinOccurrences, an
	// HIBP_BREACHED issue is added. On network or API errors, the check
	// is skipped (graceful degradation). Use the hibp package to obtain
	// a Client that implements this interface.
	HIBPChecker interface {
		Check(password string) (breached bool, count int, err error)
	}

	// HIBPMinOccurrences is the minimum breach count required to report
	// an HIBP_BREACHED issue. Only used when HIBPChecker or HIBPResult is set.
	// Default: 1 (report if found in any breach).
	HIBPMinOccurrences int

	// HIBPResult, when non-nil, is used instead of calling HIBPChecker. This
	// allows callers (e.g. browser WASM) to perform the HIBP lookup outside Go
	// and pass the result in, avoiding blocking or CORS issues. When set,
	// HIBPChecker is ignored for this check.
	HIBPResult *HIBPCheckResult

	// ConstantTimeMode, when true, uses constant-time string comparison and
	// substring checks in dictionary lookups so that response time does not
	// leak whether the password matched a blocklist entry or where it matched.
	// Default: false (faster, non-constant-time lookups).
	ConstantTimeMode bool

	// MinExecutionTimeMs is the minimum total execution time in milliseconds
	// for CheckWithConfig (and related) when ConstantTimeMode is true. The
	// function sleeps for the remaining time so that response duration does not
	// leak information. Ignored when zero or negative or when ConstantTimeMode
	// is false. Default: 0 (no padding).
	MinExecutionTimeMs int
}

// DefaultConfig returns the recommended configuration with sensible
// defaults for general-purpose password validation.
func DefaultConfig() Config {
	return Config{
		MinLength:        12,
		RequireUpper:     true,
		RequireLower:     true,
		RequireDigit:     true,
		RequireSymbol:    true,
		MaxRepeats:       3,
		PatternMinLength: 4,
		MaxIssues:        5,
	}
}

// Validate checks the configuration for invalid values and returns
// an error describing the first problem found.
//
// Rules:
//   - MinLength must be >= 1
//   - MaxRepeats must be >= 2
//   - PatternMinLength must be >= 3
//   - MaxIssues must be >= 0
//   - MinExecutionTimeMs must be >= 0 when set
func (c Config) Validate() error {
	if c.MinLength < 1 {
		return fmt.Errorf("passcheck: MinLength must be >= 1, got %d", c.MinLength)
	}
	if c.MaxRepeats < 2 {
		return fmt.Errorf("passcheck: MaxRepeats must be >= 2, got %d", c.MaxRepeats)
	}
	if c.PatternMinLength < 3 {
		return fmt.Errorf("passcheck: PatternMinLength must be >= 3, got %d", c.PatternMinLength)
	}
	if c.MaxIssues < 0 {
		return fmt.Errorf("passcheck: MaxIssues must be >= 0, got %d", c.MaxIssues)
	}
	if c.MinExecutionTimeMs < 0 {
		return fmt.Errorf("passcheck: MinExecutionTimeMs must be >= 0, got %d", c.MinExecutionTimeMs)
	}
	return nil
}
