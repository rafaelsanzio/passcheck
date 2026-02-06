package dictionary

// Options configures the behavior of dictionary checks.
//
// Use [DefaultOptions] to obtain the recommended defaults, then
// override individual fields as needed.
type Options struct {
	// CustomPasswords is an additional list of passwords to check against,
	// merged with the built-in common password set. Entries should be
	// lowercase. Nil or empty means use only the built-in list.
	CustomPasswords []string

	// CustomWords is an additional list of words to check for substring
	// matches, merged with the built-in common word list. Entries should
	// be lowercase. Nil or empty means use only the built-in list.
	CustomWords []string

	// DisableLeet disables leetspeak normalization during dictionary
	// checks. When true, only the plain (lowercased) password is checked;
	// substitutions like @ → a, 0 → o, $ → s are not applied.
	//
	// Default: false (leet normalization enabled).
	DisableLeet bool
}

// DefaultOptions returns the recommended dictionary options.
//
// These match the library-wide defaults:
//
//	CustomPasswords: nil   (built-in only)
//	CustomWords:     nil   (built-in only)
//	DisableLeet:     false (leet normalization enabled)
func DefaultOptions() Options {
	return Options{}
}
