package passcheck

import (
	"errors"
	"fmt"
)

// ErrInvalidConfig is returned when the configuration fails validation.
var ErrInvalidConfig = errors.New("passcheck: invalid configuration")


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

	// PassphraseMode, when true, enables passphrase-friendly scoring. When a
	// password is detected as a passphrase (has at least MinWords distinct words),
	// word-based entropy is used instead of character-based entropy, and dictionary
	// penalties are reduced. Word boundaries are detected using spaces, hyphens,
	// camelCase, and snake_case. Default: false (standard password scoring).
	PassphraseMode bool

	// MinWords is the minimum number of distinct words required to consider a
	// password a passphrase. Only used when PassphraseMode is true.
	// Default: 4 (NIST SP 800-63B recommends 4+ words for passphrases).
	MinWords int

	// WordDictSize is the assumed dictionary size for word-based entropy calculation
	// when PassphraseMode is true and a passphrase is detected. Used in the diceware
	// model: entropy = wordCount × log2(WordDictSize). Default: 7776 (diceware standard).
	WordDictSize int

	// MinExecutionTimeMs is the minimum total execution time in milliseconds
	// for CheckWithConfig (and related) when ConstantTimeMode is true. The
	// function sleeps for the remaining time so that response duration does not
	// leak information. Ignored when zero or negative or when ConstantTimeMode
	// is false. Default: 0 (no padding).
	MinExecutionTimeMs int

	// EntropyMode controls how entropy is calculated. Simple mode uses the
	// basic character-pool × length formula. Advanced mode reduces entropy
	// for detected patterns (keyboard walks, sequences). PatternAware mode
	// includes Markov-chain analysis for character transition probabilities.
	// Default: EntropyModeSimple (backward-compatible).
	EntropyMode EntropyMode

	// PenaltyWeights allows customization of penalty multipliers and entropy
	// weight for scoring. When nil, default weights are used (all multipliers = 1.0).
	// Organizations can adjust these to prioritize different security concerns.
	// For example, setting DictionaryMatch to 2.0 doubles dictionary penalties,
	// while setting EntropyWeight to 0.5 reduces the influence of entropy on the score.
	PenaltyWeights *PenaltyWeights
}

// PenaltyWeights allows customization of penalty multipliers and entropy weight
// for password strength scoring. All weights default to 1.0 when nil or when
// individual fields are zero.
//
// Example: To double dictionary penalties and reduce entropy influence:
//
//	weights := &passcheck.PenaltyWeights{
//		DictionaryMatch: 2.0,
//		EntropyWeight:   0.5,
//	}
//	cfg.PenaltyWeights = weights
type PenaltyWeights struct {
	// RuleViolation multiplies penalties for rule violations (length, charset, etc.).
	// Default: 1.0 (PenaltyPerRule = 5 per violation).
	RuleViolation float64

	// PatternMatch multiplies penalties for pattern detections (keyboard walks, sequences).
	// Default: 1.0 (PenaltyPerPattern = 10 per pattern).
	PatternMatch float64

	// DictionaryMatch multiplies penalties for dictionary matches (common passwords, words).
	// Default: 1.0 (PenaltyPerDictMatch = 15 per match).
	DictionaryMatch float64

	// ContextMatch multiplies penalties for context-aware detections (username, email).
	// Default: 1.0 (PenaltyPerContext = 20 per match).
	ContextMatch float64

	// HIBPBreach multiplies penalties for HIBP breach database matches.
	// Default: 1.0 (PenaltyPerHIBP = 25 per breach).
	HIBPBreach float64

	// EntropyWeight multiplies the base score derived from entropy.
	// Default: 1.0 (entropy contributes fully to base score).
	// Values < 1.0 reduce entropy influence; values > 1.0 increase it.
	EntropyWeight float64
}

// EntropyMode specifies the entropy calculation method.
type EntropyMode string

const (
	// EntropyModeSimple uses the basic character-pool × length formula.
	// This is the default and backward-compatible mode.
	EntropyModeSimple EntropyMode = "simple"

	// EntropyModeAdvanced reduces entropy for detected patterns (keyboard
	// walks, sequences, repeated blocks) to provide more accurate strength
	// estimates for patterned passwords.
	EntropyModeAdvanced EntropyMode = "advanced"

	// EntropyModePatternAware includes full pattern analysis plus Markov-chain
	// analysis for character transition probabilities, providing the most
	// accurate entropy estimates.
	EntropyModePatternAware EntropyMode = "pattern-aware"
)

// DefaultConfig returns the recommended configuration with sensible
// defaults for general-purpose password validation.
//
// Note: Presets set only a subset of fields; other fields retain zero
// values and are interpreted as defaults (see Validate).
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
		PassphraseMode:   false,
		MinWords:         4,
		WordDictSize:     7776,
		EntropyMode:      EntropyModeSimple,
	}
}

// Validate checks the configuration for invalid values and returns
// an error describing the first problem found.
//
// Callers can use errors.Is(err, passcheck.ErrInvalidConfig) to identify
// validation failures.
func (c Config) Validate() error {
	type check struct {
		ok  bool
		msg string
	}
	checks := []check{
		{c.MinLength >= 1, fmt.Sprintf("MinLength must be >= 1, got %d", c.MinLength)},
		{c.MaxRepeats >= 2, fmt.Sprintf("MaxRepeats must be >= 2, got %d", c.MaxRepeats)},
		{c.PatternMinLength >= 3, fmt.Sprintf("PatternMinLength must be >= 3, got %d", c.PatternMinLength)},
		{c.MaxIssues >= 0, fmt.Sprintf("MaxIssues must be >= 0, got %d", c.MaxIssues)},
		{c.MinExecutionTimeMs >= 0, fmt.Sprintf("MinExecutionTimeMs must be >= 0, got %d", c.MinExecutionTimeMs)},
	}

	if c.PassphraseMode {
		checks = append(checks,
			check{c.MinWords >= 1, fmt.Sprintf("MinWords must be >= 1 when PassphraseMode is true, got %d", c.MinWords)},
			check{c.WordDictSize >= 2, fmt.Sprintf("WordDictSize must be >= 2 when PassphraseMode is true, got %d", c.WordDictSize)},
		)
	}

	for _, k := range checks {
		if !k.ok {
			return fmt.Errorf("%w: %s", ErrInvalidConfig, k.msg)
		}
	}

	if c.PenaltyWeights != nil {
		if err := c.PenaltyWeights.Validate(); err != nil {
			return err
		}
	}
	return nil
}


// Validate checks that all penalty weights are non-negative.
// Zero values are treated as defaults (1.0) during scoring.
func (w *PenaltyWeights) Validate() error {
	type check struct {
		ok  bool
		msg string
	}
	checks := []check{
		{w.RuleViolation >= 0, fmt.Sprintf("PenaltyWeights.RuleViolation must be >= 0, got %f", w.RuleViolation)},
		{w.PatternMatch >= 0, fmt.Sprintf("PenaltyWeights.PatternMatch must be >= 0, got %f", w.PatternMatch)},
		{w.DictionaryMatch >= 0, fmt.Sprintf("PenaltyWeights.DictionaryMatch must be >= 0, got %f", w.DictionaryMatch)},
		{w.ContextMatch >= 0, fmt.Sprintf("PenaltyWeights.ContextMatch must be >= 0, got %f", w.ContextMatch)},
		{w.HIBPBreach >= 0, fmt.Sprintf("PenaltyWeights.HIBPBreach must be >= 0, got %f", w.HIBPBreach)},
		{w.EntropyWeight >= 0, fmt.Sprintf("PenaltyWeights.EntropyWeight must be >= 0, got %f", w.EntropyWeight)},
	}

	for _, k := range checks {
		if !k.ok {
			return fmt.Errorf("%w: %s", ErrInvalidConfig, k.msg)
		}
	}
	return nil
}

