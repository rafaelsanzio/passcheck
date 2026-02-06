package patterns

// Options configures the behavior of pattern detection checks.
//
// Use [DefaultOptions] to obtain the recommended defaults, then
// override individual fields as needed.
type Options struct {
	// KeyboardMinLen is the minimum number of consecutive keyboard-adjacent
	// characters that trigger a keyboard-pattern detection.
	KeyboardMinLen int

	// SequenceMinLen is the minimum number of characters in an arithmetic
	// progression that trigger a sequence detection.
	SequenceMinLen int
}

// DefaultOptions returns the recommended pattern options.
//
// These match the library-wide defaults:
//
//	KeyboardMinLen: 4
//	SequenceMinLen: 4
func DefaultOptions() Options {
	return Options{
		KeyboardMinLen: DefaultKeyboardMinLen,
		SequenceMinLen: DefaultSequenceMinLen,
	}
}
