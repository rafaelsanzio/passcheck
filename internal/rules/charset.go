package rules

import "unicode"

// charsetAnalysis holds the results of scanning a password for character types.
type charsetAnalysis struct {
	hasUpper  bool
	hasLower  bool
	hasDigit  bool
	hasSymbol bool
}

// analyzeCharsets performs a single pass over the password to determine
// which character sets are present.
func analyzeCharsets(password string) charsetAnalysis {
	var cs charsetAnalysis
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			cs.hasUpper = true
		case unicode.IsLower(r):
			cs.hasLower = true
		case unicode.IsDigit(r):
			cs.hasDigit = true
		case !unicode.IsSpace(r) && !unicode.IsControl(r):
			// Anything that isn't upper, lower, digit, space, or control
			// is treated as a symbol.
			cs.hasSymbol = true
		}
	}
	return cs
}

// checkCharsets verifies the password contains characters from the
// character sets enabled in opts (uppercase, lowercase, digits, symbols).
//
// It performs a single pass over the password for efficiency, then reports
// all missing character sets at once.
func checkCharsets(password string, opts Options) []string {
	if password == "" {
		return nil
	}

	cs := analyzeCharsets(password)

	var issues []string
	if opts.RequireUpper && !cs.hasUpper {
		issues = append(issues, "Add at least one uppercase letter")
	}
	if opts.RequireLower && !cs.hasLower {
		issues = append(issues, "Add at least one lowercase letter")
	}
	if opts.RequireDigit && !cs.hasDigit {
		issues = append(issues, "Add at least one digit")
	}
	if opts.RequireSymbol && !cs.hasSymbol {
		issues = append(issues, "Add at least one symbol (!@#$%^&*...)")
	}
	return issues
}
