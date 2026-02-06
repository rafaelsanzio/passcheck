// Package issue defines a structured representation of password check
// findings used across rules, patterns, dictionary, and feedback packages.
package issue

// Severity levels — higher is more critical.
const (
	SeverityLow  = 1 // rule violations (length, charset, etc.)
	SeverityMed  = 2 // pattern detection (keyboard, sequence, block)
	SeverityHigh = 3 // dictionary matches (common password, common word)
)

// Category names for grouping.
const (
	CategoryRule      = "rule"
	CategoryPattern   = "pattern"
	CategoryDictionary = "dictionary"
)

// Issue codes — stable identifiers for programmatic handling.
const (
	// Rules
	CodeRuleTooShort     = "RULE_TOO_SHORT"
	CodeRuleNoUpper      = "RULE_NO_UPPER"
	CodeRuleNoLower      = "RULE_NO_LOWER"
	CodeRuleNoDigit      = "RULE_NO_DIGIT"
	CodeRuleNoSymbol     = "RULE_NO_SYMBOL"
	CodeRuleWhitespace   = "RULE_WHITESPACE"
	CodeRuleControlChar  = "RULE_CONTROL_CHAR"
	CodeRuleRepeatedChars = "RULE_REPEATED_CHARS"

	// Patterns
	CodePatternKeyboard    = "PATTERN_KEYBOARD"
	CodePatternSequence    = "PATTERN_SEQUENCE"
	CodePatternBlock       = "PATTERN_BLOCK"
	CodePatternSubstitution = "PATTERN_SUBSTITUTION"

	// Dictionary
	CodeDictCommonPassword = "DICT_COMMON_PASSWORD"
	CodeDictLeetVariant    = "DICT_LEET_VARIANT"
	CodeDictCommonWord     = "DICT_COMMON_WORD"
	CodeDictCommonWordSub  = "DICT_COMMON_WORD_SUB"
)

// Issue represents a single finding from a password check.
type Issue struct {
	Code     string // Stable identifier for programmatic handling
	Message  string // Human-readable description
	Category string // "rule", "pattern", "dictionary"
	Severity int    // 1 (low) – 3 (high)
}

// New creates an Issue with the given fields.
func New(code, message, category string, severity int) Issue {
	return Issue{
		Code:     code,
		Message:  message,
		Category: category,
		Severity: severity,
	}
}
