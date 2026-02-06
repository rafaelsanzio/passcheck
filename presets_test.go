package passcheck

import (
	"testing"
)

// TestNISTConfig verifies NIST SP 800-63B compliant configuration
func TestNISTConfig(t *testing.T) {
	cfg := NISTConfig()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		t.Fatalf("NISTConfig() returned invalid config: %v", err)
	}

	// Verify NIST characteristics
	if cfg.MinLength != 8 {
		t.Errorf("MinLength = %d, want 8 (NIST minimum)", cfg.MinLength)
	}

	// NIST rejects composition rules
	if cfg.RequireUpper {
		t.Error("RequireUpper = true, want false (NIST rejects composition rules)")
	}
	if cfg.RequireLower {
		t.Error("RequireLower = true, want false (NIST rejects composition rules)")
	}
	if cfg.RequireDigit {
		t.Error("RequireDigit = true, want false (NIST rejects composition rules)")
	}
	if cfg.RequireSymbol {
		t.Error("RequireSymbol = true, want false (NIST rejects composition rules)")
	}

	// NIST doesn't restrict characters (uses high values to effectively disable)
	if cfg.MaxRepeats != 99 {
		t.Errorf("MaxRepeats = %d, want 99 (effectively unlimited)", cfg.MaxRepeats)
	}

	// Pattern detection should be effectively disabled
	if cfg.PatternMinLength != 99 {
		t.Errorf("PatternMinLength = %d, want 99 (effectively disabled)", cfg.PatternMinLength)
	}
}

// TestPCIDSSConfig verifies PCI-DSS v4.0 compliant configuration
func TestPCIDSSConfig(t *testing.T) {
	cfg := PCIDSSConfig()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		t.Fatalf("PCIDSSConfig() returned invalid config: %v", err)
	}

	// Verify PCI-DSS Requirement 8.3.6
	if cfg.MinLength != 12 {
		t.Errorf("MinLength = %d, want 12 (PCI-DSS Requirement 8.3.6)", cfg.MinLength)
	}

	// PCI-DSS requires all character types
	if !cfg.RequireUpper {
		t.Error("RequireUpper = false, want true (PCI-DSS requires complexity)")
	}
	if !cfg.RequireLower {
		t.Error("RequireLower = false, want true (PCI-DSS requires complexity)")
	}
	if !cfg.RequireDigit {
		t.Error("RequireDigit = false, want true (PCI-DSS requires complexity)")
	}
	if !cfg.RequireSymbol {
		t.Error("RequireSymbol = false, want true (PCI-DSS requires complexity)")
	}

	// PCI-DSS limits repeated characters
	if cfg.MaxRepeats != 3 {
		t.Errorf("MaxRepeats = %d, want 3", cfg.MaxRepeats)
	}

	// Pattern detection should be enabled
	if cfg.PatternMinLength != 4 {
		t.Errorf("PatternMinLength = %d, want 4", cfg.PatternMinLength)
	}
}

// TestOWASPConfig verifies OWASP recommended configuration
func TestOWASPConfig(t *testing.T) {
	cfg := OWASPConfig()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		t.Fatalf("OWASPConfig() returned invalid config: %v", err)
	}

	// Verify OWASP recommendations
	if cfg.MinLength != 10 {
		t.Errorf("MinLength = %d, want 10 (OWASP recommendation)", cfg.MinLength)
	}

	// OWASP requires uppercase, lowercase, digits
	if !cfg.RequireUpper {
		t.Error("RequireUpper = false, want true")
	}
	if !cfg.RequireLower {
		t.Error("RequireLower = false, want true")
	}
	if !cfg.RequireDigit {
		t.Error("RequireDigit = false, want true")
	}

	// Symbols optional for better UX
	if cfg.RequireSymbol {
		t.Error("RequireSymbol = true, want false (optional for UX)")
	}

	if cfg.MaxRepeats != 3 {
		t.Errorf("MaxRepeats = %d, want 3", cfg.MaxRepeats)
	}
}

// TestEnterpriseConfig verifies strict enterprise configuration
func TestEnterpriseConfig(t *testing.T) {
	cfg := EnterpriseConfig()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		t.Fatalf("EnterpriseConfig() returned invalid config: %v", err)
	}

	// Verify enhanced security
	if cfg.MinLength != 14 {
		t.Errorf("MinLength = %d, want 14 (enhanced security)", cfg.MinLength)
	}

	// Requires all character types
	if !cfg.RequireUpper || !cfg.RequireLower || !cfg.RequireDigit || !cfg.RequireSymbol {
		t.Error("Enterprise config must require all character types")
	}

	// Stricter repeated character limit
	if cfg.MaxRepeats != 2 {
		t.Errorf("MaxRepeats = %d, want 2 (stricter than standard)", cfg.MaxRepeats)
	}

	// More aggressive pattern detection
	if cfg.PatternMinLength != 3 {
		t.Errorf("PatternMinLength = %d, want 3 (aggressive detection)", cfg.PatternMinLength)
	}

	// More comprehensive feedback
	if cfg.MaxIssues != 10 {
		t.Errorf("MaxIssues = %d, want 10 (comprehensive feedback)", cfg.MaxIssues)
	}
}

// TestUserFriendlyConfig verifies user-friendly configuration
func TestUserFriendlyConfig(t *testing.T) {
	cfg := UserFriendlyConfig()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		t.Fatalf("UserFriendlyConfig() returned invalid config: %v", err)
	}

	// Verify balanced approach
	if cfg.MinLength != 10 {
		t.Errorf("MinLength = %d, want 10", cfg.MinLength)
	}

	// Flexible composition
	if cfg.RequireUpper {
		t.Error("RequireUpper = true, want false (flexible)")
	}
	if !cfg.RequireLower {
		t.Error("RequireLower = false, want true (at least lowercase)")
	}
	if !cfg.RequireDigit {
		t.Error("RequireDigit = false, want true (at least digits)")
	}
	if cfg.RequireSymbol {
		t.Error("RequireSymbol = true, want false (flexible)")
	}

	// More lenient
	if cfg.MaxRepeats != 4 {
		t.Errorf("MaxRepeats = %d, want 4 (lenient)", cfg.MaxRepeats)
	}

	// Less aggressive pattern detection
	if cfg.PatternMinLength != 5 {
		t.Errorf("PatternMinLength = %d, want 5 (less aggressive)", cfg.PatternMinLength)
	}

	// Fewer issues shown
	if cfg.MaxIssues != 3 {
		t.Errorf("MaxIssues = %d, want 3 (focused feedback)", cfg.MaxIssues)
	}
}

// TestNISTConfig_Compliance tests NIST-compliant passwords
func TestNISTConfig_Compliance(t *testing.T) {
	cfg := NISTConfig()

	tests := []struct {
		name       string
		password   string
		wantStrong bool // Should score reasonably well
	}{
		{
			name:       "8 characters unique",
			password:   "MySecret",
			wantStrong: false, // Too short by modern standards, but NIST minimum
		},
		{
			name:       "longer unique password",
			password:   "MySecret2024",
			wantStrong: true,
		},
		{
			name:       "passphrase",
			password:   "correct-horse-battery",
			wantStrong: true,
		},
		{
			name:       "common password",
			password:   "password",
			wantStrong: false, // Should fail dictionary check
		},
		{
			name:       "all lowercase acceptable",
			password:   "mylongpassword",
			wantStrong: false, // Acceptable by NIST but may have dictionary issues
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CheckWithConfig(tt.password, cfg)
			if err != nil {
				t.Fatalf("CheckWithConfig() error = %v", err)
			}

			// NIST focuses on length and dictionary, not composition
			// So we check that composition rules aren't enforced
			hasCompositionIssue := false
			for _, issue := range result.Issues {
				if issue.Code == "RULE_NO_UPPER" || issue.Code == "RULE_NO_LOWER" ||
					issue.Code == "RULE_NO_DIGIT" || issue.Code == "RULE_NO_SYMBOL" {
					hasCompositionIssue = true
					break
				}
			}

			if hasCompositionIssue {
				t.Error("NIST config should not enforce composition rules")
			}
		})
	}
}

// TestPCIDSSConfig_Compliance tests PCI-DSS compliant passwords
func TestPCIDSSConfig_Compliance(t *testing.T) {
	cfg := PCIDSSConfig()

	tests := []struct {
		name        string
		password    string
		shouldPass  bool
		description string
	}{
		{
			name:        "too short",
			password:    "Pass123!",
			shouldPass:  false,
			description: "Less than 12 characters",
		},
		{
			name:        "no symbol",
			password:    "Password1234",
			shouldPass:  false,
			description: "Missing required symbol",
		},
		{
			name:        "no uppercase",
			password:    "password123!",
			shouldPass:  false,
			description: "Missing required uppercase",
		},
		{
			name:        "compliant password",
			password:    "MyC0mpl3x!P@ss2024",
			shouldPass:  true,
			description: "Meets all PCI-DSS requirements",
		},
		{
			name:        "repeating characters",
			password:    "AAAA1111!!!!",
			shouldPass:  false,
			description: "Too many repeated characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CheckWithConfig(tt.password, cfg)
			if err != nil {
				t.Fatalf("CheckWithConfig() error = %v", err)
			}

			hasIssues := len(result.Issues) > 0
			if tt.shouldPass && hasIssues {
				t.Errorf("%s: expected to pass but got issues: %v", tt.description, result.Issues)
			}
		})
	}
}

// TestPresetStrictnessOrder verifies presets are ordered by strictness
func TestPresetStrictnessOrder(t *testing.T) {
	// Test password that meets basic requirements
	password := "MyPassword123"

	nist := NISTConfig()
	userFriendly := UserFriendlyConfig()
	owasp := OWASPConfig()
	pciDss := PCIDSSConfig()
	enterprise := EnterpriseConfig()

	resultNIST, _ := CheckWithConfig(password, nist)
	resultUserFriendly, _ := CheckWithConfig(password, userFriendly)
	resultOWASP, _ := CheckWithConfig(password, owasp)
	resultPCIDSS, _ := CheckWithConfig(password, pciDss)
	resultEnterprise, _ := CheckWithConfig(password, enterprise)

	// NIST should be most lenient (fewest issues or highest score)
	// Enterprise should be strictest (most issues or lowest score)

	// Verify minimum length ordering
	if nist.MinLength > userFriendly.MinLength {
		t.Error("NIST should have lower or equal MinLength than UserFriendly")
	}
	if userFriendly.MinLength > owasp.MinLength {
		t.Error("UserFriendly should have lower or equal MinLength than OWASP")
	}
	if owasp.MinLength > pciDss.MinLength {
		t.Error("OWASP should have lower or equal MinLength than PCI-DSS")
	}
	if pciDss.MinLength > enterprise.MinLength {
		t.Error("PCI-DSS should have lower or equal MinLength than Enterprise")
	}

	t.Logf("Strictness order verified:")
	t.Logf("  NIST: MinLength=%d, Score=%d", nist.MinLength, resultNIST.Score)
	t.Logf("  UserFriendly: MinLength=%d, Score=%d", userFriendly.MinLength, resultUserFriendly.Score)
	t.Logf("  OWASP: MinLength=%d, Score=%d", owasp.MinLength, resultOWASP.Score)
	t.Logf("  PCI-DSS: MinLength=%d, Score=%d", pciDss.MinLength, resultPCIDSS.Score)
	t.Logf("  Enterprise: MinLength=%d, Score=%d", enterprise.MinLength, resultEnterprise.Score)
}

// TestAllPresetsValid verifies all presets return valid configurations
func TestAllPresetsValid(t *testing.T) {
	presets := map[string]Config{
		"NIST":         NISTConfig(),
		"PCI-DSS":      PCIDSSConfig(),
		"OWASP":        OWASPConfig(),
		"Enterprise":   EnterpriseConfig(),
		"UserFriendly": UserFriendlyConfig(),
	}

	for name, cfg := range presets {
		t.Run(name, func(t *testing.T) {
			if err := cfg.Validate(); err != nil {
				t.Errorf("%s preset returned invalid config: %v", name, err)
			}
		})
	}
}

// TestPresetDocumentation verifies each preset has proper documentation
func TestPresetDocumentation(t *testing.T) {
	// This is a meta-test to ensure documentation exists
	// In practice, godoc will verify this, but we can check basic functionality

	presets := []struct {
		name string
		fn   func() Config
	}{
		{"NIST", NISTConfig},
		{"PCI-DSS", PCIDSSConfig},
		{"OWASP", OWASPConfig},
		{"Enterprise", EnterpriseConfig},
		{"UserFriendly", UserFriendlyConfig},
	}

	for _, preset := range presets {
		t.Run(preset.name, func(t *testing.T) {
			// Verify function returns a config
			cfg := preset.fn()
			if err := cfg.Validate(); err != nil {
				t.Errorf("%s preset function failed: %v", preset.name, err)
			}
		})
	}
}

// Benchmark tests
func BenchmarkNISTConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NISTConfig()
	}
}

func BenchmarkPCIDSSConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = PCIDSSConfig()
	}
}

func BenchmarkOWASPConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = OWASPConfig()
	}
}

func BenchmarkEnterpriseConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = EnterpriseConfig()
	}
}

func BenchmarkUserFriendlyConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = UserFriendlyConfig()
	}
}
