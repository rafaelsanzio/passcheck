package issue

import "testing"

func TestNew(t *testing.T) {
	const (
		code     = "TEST_CODE"
		message  = "test message"
		category = "test_category"
		severity = 2
	)

	iss := New(code, message, category, severity)

	if iss.Code != code {
		t.Errorf("Code = %q, want %q", iss.Code, code)
	}
	if iss.Message != message {
		t.Errorf("Message = %q, want %q", iss.Message, message)
	}
	if iss.Category != category {
		t.Errorf("Category = %q, want %q", iss.Category, category)
	}
	if iss.Severity != severity {
		t.Errorf("Severity = %d, want %d", iss.Severity, severity)
	}
	if iss.Pattern != "" {
		t.Errorf("Pattern = %q, want empty for New", iss.Pattern)
	}
}

func TestNewPattern(t *testing.T) {
	const (
		code     = CodePatternKeyboard
		message  = "Keyboard pattern detected"
		pattern  = "qwerty"
		category = CategoryPattern
		severity = SeverityMed
	)

	iss := NewPattern(code, message, pattern, category, severity)

	if iss.Code != code {
		t.Errorf("Code = %q, want %q", iss.Code, code)
	}
	if iss.Message != message {
		t.Errorf("Message = %q, want %q", iss.Message, message)
	}
	if iss.Category != category {
		t.Errorf("Category = %q, want %q", iss.Category, category)
	}
	if iss.Severity != severity {
		t.Errorf("Severity = %d, want %d", iss.Severity, severity)
	}
	if iss.Pattern != pattern {
		t.Errorf("Pattern = %q, want %q", iss.Pattern, pattern)
	}
}

