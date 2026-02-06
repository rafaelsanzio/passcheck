package passcheck

// NISTConfig returns a configuration compliant with NIST SP 800-63B
// Digital Identity Guidelines.
//
// NIST emphasizes password length over complexity, rejecting traditional
// composition rules (required character types) in favor of checking against
// breach databases and common passwords.
//
// Key characteristics:
//   - Minimum 8 characters (NIST minimum requirement)
//   - No composition rules (no required uppercase, lowercase, digits, or symbols)
//   - No character restrictions (allows maximum user flexibility)
//   - Dictionary checking enabled to prevent common passwords
//   - Pattern detection disabled (focuses on length and uniqueness)
//
// Suitable for:
//   - General-purpose applications
//   - Consumer-facing services
//   - Applications prioritizing user experience
//
// Reference: NIST SP 800-63B Section 5.1.1
// https://pages.nist.gov/800-63-3/sp800-63b.html
//
// Example:
//
//	cfg := passcheck.NISTConfig()
//	result, _ := passcheck.CheckWithConfig("MySecret2024", cfg)
//	// Accepts 8+ character passwords without composition requirements
func NISTConfig() Config {
	return Config{
		MinLength:        8,
		RequireUpper:     false,
		RequireLower:     false,
		RequireDigit:     false,
		RequireSymbol:    false,
		MaxRepeats:       99, // Effectively unlimited (NIST doesn't restrict)
		PatternMinLength: 99, // Effectively disabled (very high threshold)
		MaxIssues:        5,
		DisableLeet:      false,
	}
}

// PCIDSSConfig returns a configuration compliant with PCI-DSS v4.0
// password requirements for payment card industry applications.
//
// PCI-DSS requires strict password complexity to protect payment card data.
// This preset enforces all composition rules and pattern detection.
//
// Key characteristics:
//   - Minimum 12 characters (PCI-DSS Requirement 8.3.6)
//   - Requires all character types (uppercase, lowercase, digits, symbols)
//   - Maximum 3 consecutive repeated characters
//   - Pattern detection enabled (keyboard walks, sequences)
//   - Dictionary checking enabled
//
// Suitable for:
//   - Payment processing systems
//   - Financial applications
//   - E-commerce platforms
//   - Any application handling payment card data
//
// Note: PCI-DSS also requires password expiration (90 days) and password
// history (4 previous passwords), which are policy requirements that must
// be enforced separately from password strength checking.
//
// Reference: PCI-DSS v4.0 Requirement 8.3.6
// https://www.pcisecuritystandards.org/
//
// Example:
//
//	cfg := passcheck.PCIDSSConfig()
//	result, _ := passcheck.CheckWithConfig("MyP@ssw0rd2024!", cfg)
//	// Enforces strict complexity for PCI-DSS compliance
func PCIDSSConfig() Config {
	return Config{
		MinLength:        12,
		RequireUpper:     true,
		RequireLower:     true,
		RequireDigit:     true,
		RequireSymbol:    true,
		MaxRepeats:       3,
		PatternMinLength: 4,
		MaxIssues:        5,
		DisableLeet:      false,
	}
}

// OWASPConfig returns a configuration following OWASP password
// recommendations for web applications.
//
// OWASP provides balanced guidance that prioritizes both security and
// usability, recommending longer passwords with reasonable complexity
// requirements.
//
// Key characteristics:
//   - Minimum 10 characters (OWASP recommendation)
//   - Requires uppercase, lowercase, and digits
//   - Symbols optional (improves usability while maintaining security)
//   - Maximum 3 consecutive repeated characters
//   - Pattern detection enabled
//   - Dictionary checking enabled
//
// Suitable for:
//   - Web applications
//   - SaaS platforms
//   - API services
//   - General business applications
//
// Reference: OWASP Authentication Cheat Sheet
// https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
//
// Example:
//
//	cfg := passcheck.OWASPConfig()
//	result, _ := passcheck.CheckWithConfig("MyPassword2024", cfg)
//	// Balanced security and usability for web applications
func OWASPConfig() Config {
	return Config{
		MinLength:        10,
		RequireUpper:     true,
		RequireLower:     true,
		RequireDigit:     true,
		RequireSymbol:    false, // Optional for better UX
		MaxRepeats:       3,
		PatternMinLength: 4,
		MaxIssues:        5,
		DisableLeet:      false,
	}
}

// EnterpriseConfig returns a strict configuration for high-security
// enterprise environments.
//
// This preset implements maximum security controls suitable for organizations
// with stringent security requirements such as government agencies, healthcare
// providers, and financial institutions.
//
// Key characteristics:
//   - Minimum 14 characters (enhanced security)
//   - Requires all character types (uppercase, lowercase, digits, symbols)
//   - Maximum 2 consecutive repeated characters (stricter than standard)
//   - Aggressive pattern detection (minimum length 3)
//   - Shows up to 10 issues for comprehensive feedback
//   - Dictionary checking enabled
//
// Suitable for:
//   - Government systems
//   - Healthcare applications (HIPAA compliance)
//   - Financial services
//   - High-security corporate environments
//   - Systems handling sensitive data
//
// Recommendation: Combine with ContextWords for maximum security by
// preventing passwords that contain usernames, email addresses, or
// company names.
//
// Example:
//
//	cfg := passcheck.EnterpriseConfig()
//	cfg.ContextWords = []string{"username", "user@company.com", "CompanyName"}
//	result, _ := passcheck.CheckWithConfig("MyC0mplex!P@ssw0rd2024", cfg)
//	// Maximum security for high-risk environments
func EnterpriseConfig() Config {
	return Config{
		MinLength:        14,
		RequireUpper:     true,
		RequireLower:     true,
		RequireDigit:     true,
		RequireSymbol:    true,
		MaxRepeats:       2,  // Stricter than default
		PatternMinLength: 3,  // More aggressive pattern detection
		MaxIssues:        10, // Show more issues for comprehensive feedback
		DisableLeet:      false,
	}
}

// UserFriendlyConfig returns a balanced configuration prioritizing
// user experience while maintaining reasonable security.
//
// This preset is designed for consumer-facing applications where user
// experience is a priority, but basic security standards must still be met.
// It requires length and some complexity without being overly restrictive.
//
// Key characteristics:
//   - Minimum 10 characters (reasonable length)
//   - Requires lowercase and digits (flexible composition)
//   - Uppercase and symbols optional (reduces user friction)
//   - Maximum 4 consecutive repeated characters (lenient)
//   - Relaxed pattern detection (minimum length 5)
//   - Shows only 3 issues (focused feedback)
//   - Dictionary checking enabled
//
// Suitable for:
//   - Consumer applications
//   - Social media platforms
//   - Low-risk web services
//   - Internal tools
//   - Prototypes and MVPs
//
// Note: While this preset prioritizes usability, consider upgrading to
// OWASPConfig() or stricter presets for production applications handling
// sensitive data.
//
// Example:
//
//	cfg := passcheck.UserFriendlyConfig()
//	result, _ := passcheck.CheckWithConfig("mypassword2024", cfg)
//	// Balanced approach for consumer applications
func UserFriendlyConfig() Config {
	return Config{
		MinLength:        10,
		RequireUpper:     false, // Flexible
		RequireLower:     true,  // At least lowercase
		RequireDigit:     true,  // At least digits
		RequireSymbol:    false,
		MaxRepeats:       4, // More lenient
		PatternMinLength: 5, // Less aggressive pattern detection
		MaxIssues:        3, // Fewer issues shown
		DisableLeet:      false,
	}
}
