package rules

// Options configures the behavior of password rule checks.
//
// Use [DefaultOptions] to obtain the recommended defaults, then
// override individual fields as needed.
type Options struct {
	// MinLength is the minimum number of runes required.
	MinLength int

	// RequireUpper requires at least one uppercase letter.
	RequireUpper bool

	// RequireLower requires at least one lowercase letter.
	RequireLower bool

	// RequireDigit requires at least one numeric digit.
	RequireDigit bool

	// RequireSymbol requires at least one symbol character.
	RequireSymbol bool

	// MaxRepeats is the maximum number of consecutive identical
	// characters allowed before an issue is reported.
	MaxRepeats int
}

// DefaultOptions returns the recommended rule options.
//
// These match the library-wide defaults:
//
//	MinLength:    12
//	RequireUpper: true
//	RequireLower: true
//	RequireDigit: true
//	RequireSymbol:true
//	MaxRepeats:   3
func DefaultOptions() Options {
	return Options{
		MinLength:     DefaultMinLength,
		RequireUpper:  true,
		RequireLower:  true,
		RequireDigit:  true,
		RequireSymbol: true,
		MaxRepeats:    DefaultMaxRepeats,
	}
}
