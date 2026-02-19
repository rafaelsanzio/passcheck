// Package passcheck provides password strength checking and validation.
//
// It evaluates passwords against multiple criteria including basic rules,
// pattern detection, dictionary checks, and entropy calculation, returning
// a comprehensive result with a score, verdict, and actionable feedback.
//
// # Usage
//
//	res := passcheck.Check("P@ssw0rd123")
//	fmt.Println(res.Score)       // 42
//	fmt.Println(res.Verdict)     // "Weak"
//	for _, iss := range res.Issues { fmt.Println(iss.Message) }
//	fmt.Println(res.Suggestions) // ["Good length (16 characters)", ...]
//
// # Custom Configuration
//
//	cfg := passcheck.DefaultConfig()
//	cfg.MinLength = 8
//	cfg.RequireSymbol = false
//	result, err := passcheck.CheckWithConfig("mypassword", cfg)
//
// # Breach database (optional)
//
// Set [Config.HIBPChecker] to a client from the [hibp] package to check
// passwords against the Have I Been Pwned API (k-anonymity; only a 5-char
// hash prefix is sent). On API errors, the check is skipped.
//
// # Real-time feedback
//
// For password strength meters and live feedback, use [CheckIncremental] or
// [CheckIncrementalWithConfig]. Pass the previous result so the API can return
// an [IncrementalDelta] indicating what changed; the UI can skip updates when
// nothing changed. Debounce input (e.g. 100–300 ms) when calling on every
// keystroke to keep the UI responsive.
//
// # Security Considerations
//
// Passwords are Go strings, which are immutable and garbage-collected.
// The library cannot zero them from memory after use. For applications
// that handle passwords as []byte (e.g. reading from an HTTP request body),
// [CheckBytes] accepts a byte slice and zeros it immediately after
// analysis, reducing the window during which plaintext resides in memory.
//
// The library never logs, prints, or persists passwords. Analysis results
// contain only aggregate scores and generic issue descriptions — never the
// password itself or sensitive substrings.
//
// A maximum input length of [MaxPasswordLength] runes is enforced to
// prevent denial-of-service through algorithmic complexity. Inputs beyond
// this limit are silently truncated for analysis purposes.
package passcheck

import (
	"strings"
	"time"

	"github.com/rafaelsanzio/passcheck/internal/context"
	"github.com/rafaelsanzio/passcheck/internal/dictionary"
	"github.com/rafaelsanzio/passcheck/internal/entropy"
	"github.com/rafaelsanzio/passcheck/internal/feedback"
	"github.com/rafaelsanzio/passcheck/internal/hibpcheck"
	"github.com/rafaelsanzio/passcheck/internal/issue"
	"github.com/rafaelsanzio/passcheck/internal/passphrase"
	"github.com/rafaelsanzio/passcheck/internal/patterns"
	"github.com/rafaelsanzio/passcheck/internal/rules"
	"github.com/rafaelsanzio/passcheck/internal/safemem"
	"github.com/rafaelsanzio/passcheck/internal/scoring"
)

// MaxPasswordLength is the maximum number of runes analyzed.
// Inputs longer than this are truncated to bound CPU and memory usage
// of the pattern-detection and dictionary-lookup phases.
const MaxPasswordLength = 1024

// Verdict constants represent the password strength levels.
const (
	VerdictVeryWeak   = "Very Weak"
	VerdictWeak       = "Weak"
	VerdictOkay       = "Okay"
	VerdictStrong     = "Strong"
	VerdictVeryStrong = "Very Strong"
)

// Issue codes — stable identifiers for programmatic handling.
// Consumers can switch on Code to react differently (e.g. "RULE_TOO_SHORT" vs "DICT_COMMON_PASSWORD").
const (
	CodeRuleTooShort        = "RULE_TOO_SHORT"
	CodeRuleNoUpper         = "RULE_NO_UPPER"
	CodeRuleNoLower         = "RULE_NO_LOWER"
	CodeRuleNoDigit         = "RULE_NO_DIGIT"
	CodeRuleNoSymbol        = "RULE_NO_SYMBOL"
	CodeRuleWhitespace      = "RULE_WHITESPACE"
	CodeRuleControlChar     = "RULE_CONTROL_CHAR"
	CodeRuleRepeatedChars   = "RULE_REPEATED_CHARS"
	CodePatternKeyboard     = "PATTERN_KEYBOARD"
	CodePatternSequence     = "PATTERN_SEQUENCE"
	CodePatternBlock        = "PATTERN_BLOCK"
	CodePatternSubstitution = "PATTERN_SUBSTITUTION"
	CodeDictCommonPassword  = "DICT_COMMON_PASSWORD"
	CodeDictLeetVariant     = "DICT_LEET_VARIANT"
	CodeDictCommonWord      = "DICT_COMMON_WORD"
	CodeDictCommonWordSub   = "DICT_COMMON_WORD_SUB"
	CodeHIBPBreached        = "HIBP_BREACHED"
	CodeContextWord         = "CONTEXT_WORD"
)

// Issue represents a single finding from a password check.
type Issue struct {
	Code     string `json:"code"`     // Stable identifier (e.g. "RULE_TOO_SHORT", "DICT_COMMON_PASSWORD")
	Message  string `json:"message"`  // Human-readable description
	Category string `json:"category"` // "rule", "pattern", "dictionary"
	Severity int    `json:"severity"` // 1 (low) – 3 (high)
}

// Result holds the outcome of a password strength check.
type Result struct {
	// Score is the overall password strength score from 0 (weakest) to 100 (strongest).
	Score int `json:"score"`

	// Verdict is a human-readable strength label.
	// One of: "Very Weak", "Weak", "Okay", "Strong", "Very Strong".
	Verdict string `json:"verdict"`

	// Issues is a deduplicated, priority-sorted list of structured problems
	// found with the password. Use [Result.IssueMessages] for a []string of
	// messages only (backward compatibility).
	Issues []Issue `json:"issues"`

	// Suggestions contains positive feedback about the password's
	// strengths (e.g. "Good length", "No common patterns detected").
	// Empty when the password has no notable strengths.
	Suggestions []string `json:"suggestions"`

	// Entropy is the estimated entropy of the password in bits.
	Entropy float64 `json:"entropy"`
}

// IssueMessages returns the human-readable message for each issue, in order.
// Use this when migrating from the previous Result.Issues []string API.
func (r Result) IssueMessages() []string {
	if len(r.Issues) == 0 {
		return nil
	}
	out := make([]string, len(r.Issues))
	for i, iss := range r.Issues {
		out[i] = iss.Message
	}
	return out
}

// IncrementalDelta describes what changed between a previous check result and the
// current one. Use it to avoid redundant UI updates when using [CheckIncrementalWithConfig].
type IncrementalDelta struct {
	// ScoreChanged is true if the score differs from the previous result.
	ScoreChanged bool
	// IssuesChanged is true if the issues list (codes or messages) differs from the previous result.
	IssuesChanged bool
	// SuggestionsChanged is true if the suggestions list differs from the previous result.
	SuggestionsChanged bool
}

// Check evaluates the strength of a password using the default
// configuration and returns a Result.
//
// This is a convenience wrapper around [CheckWithConfig] using
// [DefaultConfig]. It never returns an error because the default
// configuration is always valid.
func Check(password string) Result {
	// DefaultConfig is guaranteed valid — error is always nil.
	result, _ := CheckWithConfig(password, DefaultConfig())
	return result
}

// CheckWithConfig evaluates the strength of a password using a custom
// configuration. It returns an error if the configuration is invalid.
//
// It runs the password through multiple checks:
//   - Basic rules (length, character sets, repeated characters)
//   - Pattern detection (keyboard patterns, sequences, repeated blocks)
//   - Dictionary checks (common passwords, leetspeak variants)
//   - Entropy calculation
//
// Issues are deduplicated, sorted by severity, and limited to cfg.MaxIssues.
// Positive suggestions are generated for the password's strengths.
//
// Passwords longer than [MaxPasswordLength] runes are truncated before
// analysis to prevent excessive CPU usage.
func CheckWithConfig(password string, cfg Config) (Result, error) {
	if err := cfg.Validate(); err != nil {
		return Result{}, err
	}
	start := time.Now()

	// Enforce maximum length to bound algorithmic complexity.
	pw := truncate(password)

	// Map public config to internal options.
	rulesOpts := rules.Options{
		MinLength:     cfg.MinLength,
		RequireUpper:  cfg.RequireUpper,
		RequireLower:  cfg.RequireLower,
		RequireDigit:  cfg.RequireDigit,
		RequireSymbol: cfg.RequireSymbol,
		MaxRepeats:    cfg.MaxRepeats,
	}

	patternsOpts := patterns.Options{
		KeyboardMinLen: cfg.PatternMinLength,
		SequenceMinLen: cfg.PatternMinLength,
	}

	dictOpts := dictionary.Options{
		CustomPasswords: toLowerSlice(cfg.CustomPasswords),
		CustomWords:     toLowerSlice(cfg.CustomWords),
		DisableLeet:     cfg.DisableLeet,
		ConstantTime:    cfg.ConstantTimeMode,
	}

	contextOpts := context.Options{
		ContextWords: cfg.ContextWords,
	}

	hibpOpts := hibpcheck.Options{
		Checker:        cfg.HIBPChecker,
		MinOccurrences: cfg.HIBPMinOccurrences,
	}
	if cfg.HIBPResult != nil {
		hibpOpts.Result = &hibpcheck.Result{
			Breached: cfg.HIBPResult.Breached,
			Count:    cfg.HIBPResult.Count,
		}
	}

	// Collect issues by category for weighted scoring.
	issueSet := scoring.IssueSet{
		Rules:      rules.CheckWith(pw, rulesOpts),
		Patterns:   patterns.CheckWith(pw, patternsOpts),
		Dictionary: dictionary.CheckWith(pw, dictOpts),
		Context:    context.CheckWith(pw, contextOpts),
		HIBP:       hibpcheck.CheckWith(password, hibpOpts),
	}

	// Entropy calculation: use word-based entropy for passphrases if enabled,
	// otherwise use character-based entropy with the configured EntropyMode
	e, passphraseInfo := calculateEntropy(password, pw, cfg, issueSet.Patterns)

	// Convert config penalty weights to scoring weights
	var scoringWeights *scoring.Weights
	if cfg.PenaltyWeights != nil {
		scoringWeights = &scoring.Weights{
			RuleViolation:   cfg.PenaltyWeights.RuleViolation,
			PatternMatch:    cfg.PenaltyWeights.PatternMatch,
			DictionaryMatch: cfg.PenaltyWeights.DictionaryMatch,
			ContextMatch:    cfg.PenaltyWeights.ContextMatch,
			HIBPBreach:      cfg.PenaltyWeights.HIBPBreach,
			EntropyWeight:   cfg.PenaltyWeights.EntropyWeight,
		}
	}

	// Weighted scoring using the configured MinLength for bonus baseline.
	// Reduce dictionary penalties if this is a detected passphrase.
	score := scoring.CalculateWithPassphrase(e, pw, issueSet, cfg.MinLength, passphraseInfo, scoringWeights)

	// Verdict
	verdict := scoring.Verdict(score)

	// Feedback engine: dedup, prioritize, limit issues.
	refined := feedback.Refine(issueSet, cfg.MaxIssues)

	// Positive feedback for the password's strengths.
	suggestions := feedback.GeneratePositive(pw, issueSet, e)

	// Convert internal issues to public Issue type.
	issues := make([]Issue, len(refined))
	for i, iss := range refined {
		issues[i] = Issue{Code: iss.Code, Message: iss.Message, Category: iss.Category, Severity: iss.Severity}
	}
	if suggestions == nil {
		suggestions = []string{}
	}

	if cfg.ConstantTimeMode && cfg.MinExecutionTimeMs > 0 {
		safemem.SleepRemaining(start, cfg.MinExecutionTimeMs)
	}
	return Result{
		Score:       score,
		Verdict:     verdict,
		Issues:      issues,
		Suggestions: suggestions,
		Entropy:     e,
	}, nil
}

// CheckBytes evaluates password strength from a mutable byte slice
// using the default configuration.
//
// After converting the input to a string for analysis, the original byte
// slice is immediately zeroed to minimize the time plaintext resides in
// process memory. The caller should not reuse the slice after this call.
//
// Prefer CheckBytes over [Check] when the password originates from a
// mutable source (e.g. an HTTP request body or a terminal read buffer).
func CheckBytes(password []byte) Result {
	// string() copies the bytes — the original slice can be safely zeroed.
	s := string(password)
	safemem.Zero(password)
	return Check(s)
}

// CheckBytesWithConfig evaluates password strength from a mutable byte
// slice using a custom configuration. The input is zeroed after analysis.
//
// Returns an error if the configuration is invalid.
func CheckBytesWithConfig(password []byte, cfg Config) (Result, error) {
	s := string(password)
	safemem.Zero(password)
	return CheckWithConfig(s, cfg)
}

// calculateEntropy computes entropy for a password, using word-based entropy
// for passphrases when PassphraseMode is enabled, otherwise character-based entropy
// with the configured EntropyMode (simple, advanced, or pattern-aware).
// Returns the entropy value and passphrase info (nil if not a passphrase).
func calculateEntropy(password, pw string, cfg Config, patternIssues []issue.Issue) (float64, *passphrase.Info) {
	// Handle passphrase mode first (word-based entropy)
	if cfg.PassphraseMode {
		info := passphrase.Detect(password, cfg.MinWords)
		if info.IsPassphrase {
			dictSize := cfg.WordDictSize
			if dictSize < 2 {
				dictSize = passphrase.DefaultWordDictSize
			}
			return passphrase.CalculateWordEntropy(info.WordCount, dictSize), &info
		}
		// Not a passphrase, fall through to character-based entropy
	}

	// Character-based entropy with mode selection
	entropyMode := string(cfg.EntropyMode)
	if entropyMode == "" {
		entropyMode = string(EntropyModeSimple) // Default to simple for backward compatibility
	}
	return entropy.CalculateWithMode(pw, entropyMode, patternIssues), nil
}

// CheckIncremental evaluates the strength of a password using the default
// configuration and is intended for real-time feedback (e.g. strength meters).
//
// When previous is nil, the behavior is identical to [Check]. When previous
// is non-nil, a full check is performed and the new result is returned; the
// previous result is not used to skip work (callers can compare the returned
// result with previous to detect changes). For delta information and custom
// config, use [CheckIncrementalWithConfig].
//
// When used on every keystroke, callers should debounce (e.g. 100–300 ms) to
// limit CPU usage and keep the UI responsive.
func CheckIncremental(password string, previous *Result) Result {
	result, _, _ := CheckIncrementalWithConfig(password, previous, DefaultConfig())
	return result
}

// CheckIncrementalWithConfig evaluates the strength of a password using a
// custom configuration and returns the result plus an [IncrementalDelta]
// describing what changed relative to the previous result.
//
// When previous is nil, a full check is performed and the delta has all
// Changed fields set to true. When previous is non-nil, the delta indicates
// whether score, issues, or suggestions differ so the UI can skip redundant
// updates. Returns an error if the configuration is invalid.
//
// For real-time UIs, debounce input (e.g. 100–300 ms) before calling to
// avoid excessive work on every keystroke.
func CheckIncrementalWithConfig(password string, previous *Result, cfg Config) (Result, IncrementalDelta, error) {
	result, err := CheckWithConfig(password, cfg)
	if err != nil {
		return Result{}, IncrementalDelta{}, err
	}
	delta := incrementalDeltaFrom(previous, result)
	return result, delta, nil
}

// incrementalDeltaFrom builds an IncrementalDelta by comparing curr to previous.
// When previous is nil, all Changed fields are true.
func incrementalDeltaFrom(previous *Result, curr Result) IncrementalDelta {
	if previous == nil {
		return IncrementalDelta{ScoreChanged: true, IssuesChanged: true, SuggestionsChanged: true}
	}
	return IncrementalDelta{
		ScoreChanged:       previous.Score != curr.Score,
		IssuesChanged:      !issuesEqual(previous.Issues, curr.Issues),
		SuggestionsChanged: !suggestionsEqual(previous.Suggestions, curr.Suggestions),
	}
}

func issuesEqual(a, b []Issue) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Code != b[i].Code || a[i].Message != b[i].Message {
			return false
		}
	}
	return true
}

func suggestionsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// truncate returns password unchanged if it is within MaxPasswordLength
// runes, or the first MaxPasswordLength runes otherwise.
func truncate(password string) string {
	runes := []rune(password)
	if len(runes) <= MaxPasswordLength {
		return password
	}
	return string(runes[:MaxPasswordLength])
}

// toLowerSlice returns a new slice with every string lowercased.
// Returns nil if the input is nil or empty.
func toLowerSlice(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToLower(s)
	}
	return out
}
