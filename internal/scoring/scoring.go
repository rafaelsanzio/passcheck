// Package scoring implements the password strength scoring algorithm.
//
// It combines entropy with weighted heuristic penalties and bonuses to
// produce a final score (0-100) and maps that score to a human-readable
// verdict.
//
// Scoring formula:
//
//	base  = entropy × 100 / 128          (128 bits → perfect base)
//	bonus = lengthBonus + charsetBonus
//	penalty = rulesPenalty + patternsPenalty + dictionaryPenalty
//	score = clamp(base + bonus − penalty, 0, 100)
package scoring

import (
	"github.com/rafaelsanzio/passcheck/internal/entropy"
	"github.com/rafaelsanzio/passcheck/internal/issue"
	"github.com/rafaelsanzio/passcheck/internal/passphrase"
	"github.com/rafaelsanzio/passcheck/internal/rules"
)

// Penalty weights per issue category.
const (
	PenaltyPerRule      = 5  // missing charset, length, whitespace, repeats
	PenaltyPerPattern   = 10 // keyboard walk, sequence, block, substitution
	PenaltyPerDictMatch = 15 // common password, common word, leet variant
	PenaltyPerContext   = 20 // personal information (username, email, company)
	PenaltyPerHIBP      = 25 // password found in breach database (HIBP)
)

// Bonus parameters.
const (
	// DefaultMinLength is the baseline for the length bonus when using
	// [Calculate]. Derived from [rules.DefaultMinLength] to keep the
	// two packages in sync.
	DefaultMinLength  = rules.DefaultMinLength
	BonusPerExtraChar = 2  // per character beyond the configured minimum
	MaxLengthBonus    = 20 // cap on length bonus
	BonusPerCharset   = 3  // per charset type beyond the first
	MaxCharsetBonus   = 9  // cap (4 types → 3 × 3 = 9)
	BonusPassphrase   = 25 // bonus for detected passphrases (4+ words)
)

// Entropy-to-score mapping constants.
const (
	maxScoreBase = 100.0 // maximum base score (perfect entropy)
	entropyFull  = 128.0 // bits of entropy that map to maxScoreBase
)

// Score thresholds for verdict mapping.
const (
	ThresholdVeryWeak = 20
	ThresholdWeak     = 40
	ThresholdOkay     = 60
	ThresholdStrong   = 80
)

// IssueSet groups detected issues by category so the scorer can apply
// appropriate penalty weights. Each field holds the structured issues
// produced by its corresponding analysis phase.
type IssueSet struct {
	Rules      []issue.Issue // Phase 1: basic rule violations
	Patterns   []issue.Issue // Phase 2: pattern detections
	Dictionary []issue.Issue // Phase 3: dictionary matches
	Context    []issue.Issue // Phase 4: context-aware detections
	HIBP       []issue.Issue // Phase 5: breach database (HIBP)
}

// AllIssues returns a single flat slice of all issues in evaluation order.
func (s IssueSet) AllIssues() []issue.Issue {
	out := make([]issue.Issue, 0, len(s.Rules)+len(s.Patterns)+len(s.Dictionary)+len(s.Context)+len(s.HIBP))
	out = append(out, s.Rules...)
	out = append(out, s.Patterns...)
	out = append(out, s.Dictionary...)
	out = append(out, s.Context...)
	out = append(out, s.HIBP...)
	return out
}

// Calculate computes a password strength score from 0 to 100
// using the default minimum-length baseline for length bonuses.
//
// This is a convenience wrapper around [CalculateWith].
func Calculate(entropyBits float64, password string, issues IssueSet) int {
	return CalculateWith(entropyBits, password, issues, DefaultMinLength)
}

// CalculateWith computes a password strength score from 0 to 100,
// using minLength as the baseline for the length bonus calculation.
//
// The score starts from a base derived from entropy, adds bonuses for
// length and character-set diversity, and subtracts weighted penalties
// for each issue found during analysis.
func CalculateWith(entropyBits float64, password string, issues IssueSet, minLength int) int {
	// --- Base score from entropy ---
	base := entropyBits * maxScoreBase / entropyFull

	// --- Bonuses ---
	bonus := lengthBonusWith(password, minLength) + charsetBonus(password)

	// --- Penalties ---
	penalty := len(issues.Rules)*PenaltyPerRule +
		len(issues.Patterns)*PenaltyPerPattern +
		len(issues.Dictionary)*PenaltyPerDictMatch +
		len(issues.Context)*PenaltyPerContext +
		len(issues.HIBP)*PenaltyPerHIBP

	score := int(base) + bonus - penalty

	return clamp(score, 0, 100)
}

// CalculateWithPassphrase computes a password strength score from 0 to 100,
// similar to [CalculateWith], but reduces dictionary penalties when the password
// is detected as a passphrase (has multiple words). This enables passphrase-friendly
// scoring that rewards multi-word combinations.
//
// passphraseInfo can be nil if passphrase detection is disabled or the password
// is not a passphrase. When non-nil and IsPassphrase is true, dictionary penalties
// are reduced by 50% (from PenaltyPerDictMatch to PenaltyPerDictMatch/2).
func CalculateWithPassphrase(entropyBits float64, password string, issues IssueSet, minLength int, passphraseInfo *passphrase.Info) int {
	// --- Base score from entropy ---
	base := entropyBits * maxScoreBase / entropyFull

	// --- Bonuses ---
	bonus := lengthBonusWith(password, minLength) + charsetBonus(password)
	// Add passphrase bonus for multi-word passphrases
	if passphraseInfo != nil && passphraseInfo.IsPassphrase {
		bonus += BonusPassphrase
	}

	// --- Penalties ---
	// Eliminate dictionary penalties for passphrases (dictionary words are expected and desired)
	dictPenalty := PenaltyPerDictMatch
	if passphraseInfo != nil && passphraseInfo.IsPassphrase {
		dictPenalty = 0 // No dictionary penalties for passphrases
	}

	penalty := len(issues.Rules)*PenaltyPerRule +
		len(issues.Patterns)*PenaltyPerPattern +
		len(issues.Dictionary)*dictPenalty +
		len(issues.Context)*PenaltyPerContext +
		len(issues.HIBP)*PenaltyPerHIBP

	score := int(base) + bonus - penalty

	return clamp(score, 0, 100)
}

// Verdict maps a score (0-100) to a human-readable strength label.
func Verdict(score int) string {
	switch {
	case score <= ThresholdVeryWeak:
		return "Very Weak"
	case score <= ThresholdWeak:
		return "Weak"
	case score <= ThresholdOkay:
		return "Okay"
	case score <= ThresholdStrong:
		return "Strong"
	default:
		return "Very Strong"
	}
}

// lengthBonus awards extra points for passwords that exceed the default minimum length.
func lengthBonus(password string) int {
	return lengthBonusWith(password, DefaultMinLength)
}

// lengthBonusWith awards extra points for passwords that exceed minLength.
func lengthBonusWith(password string, minLength int) int {
	extra := len([]rune(password)) - minLength
	if extra <= 0 {
		return 0
	}
	bonus := extra * BonusPerExtraChar
	if bonus > MaxLengthBonus {
		bonus = MaxLengthBonus
	}
	return bonus
}

// charsetBonus awards extra points for using multiple character set types.
func charsetBonus(password string) int {
	info := entropy.AnalyzeCharsets(password)
	count := info.SetCount()
	if count <= 1 {
		return 0
	}
	bonus := (count - 1) * BonusPerCharset
	if bonus > MaxCharsetBonus {
		bonus = MaxCharsetBonus
	}
	return bonus
}

// clamp restricts v to the range [lo, hi].
func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
