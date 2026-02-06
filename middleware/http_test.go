package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- DefaultHTTPExtractor / ExtractPassword ---

func TestDefaultHTTPExtractor_ExtractPassword_NonHTTPRequest(t *testing.T) {
	ext := DefaultHTTPExtractor(Config{PasswordField: "password"})
	got, err := ext.ExtractPassword(42)
	if err != nil {
		t.Errorf("ExtractPassword(42) err = %v, want nil", err)
	}
	if got != "" {
		t.Errorf("ExtractPassword(42) = %q, want \"\"", got)
	}
}

func TestDefaultHTTPExtractor_ExtractPassword_NilRequest(t *testing.T) {
	ext := DefaultHTTPExtractor(Config{PasswordField: "password"})
	got, err := ext.ExtractPassword(nil)
	if err != nil {
		t.Errorf("ExtractPassword(nil) err = %v, want nil", err)
	}
	if got != "" {
		t.Errorf("ExtractPassword(nil) = %q, want \"\"", got)
	}
}

func TestDefaultHTTPExtractor_ExtractPassword_Form(t *testing.T) {
	ext := DefaultHTTPExtractor(Config{PasswordField: "password"})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("password=secret123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	got, err := ext.ExtractPassword(req)
	if err != nil {
		t.Fatalf("ExtractPassword err = %v", err)
	}
	if got != "secret123" {
		t.Errorf("ExtractPassword = %q, want \"secret123\"", got)
	}
}

func TestDefaultHTTPExtractor_ExtractPassword_Form_CustomField(t *testing.T) {
	ext := DefaultHTTPExtractor(Config{PasswordField: "pwd"})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("pwd=myvalue"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	got, err := ext.ExtractPassword(req)
	if err != nil {
		t.Fatalf("ExtractPassword err = %v", err)
	}
	if got != "myvalue" {
		t.Errorf("ExtractPassword = %q, want \"myvalue\"", got)
	}
}

func TestDefaultHTTPExtractor_ExtractPassword_JSON(t *testing.T) {
	ext := DefaultHTTPExtractor(Config{PasswordField: "password"})
	body := []byte(`{"password":"json-secret"}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	got, err := ext.ExtractPassword(req)
	if err != nil {
		t.Fatalf("ExtractPassword err = %v", err)
	}
	if got != "json-secret" {
		t.Errorf("ExtractPassword = %q, want \"json-secret\"", got)
	}
}

func TestDefaultHTTPExtractor_ExtractPassword_JSON_ContentTypeWithCharset(t *testing.T) {
	ext := DefaultHTTPExtractor(Config{PasswordField: "password"})
	body := []byte(`{"password":"charset-secret"}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	got, err := ext.ExtractPassword(req)
	if err != nil {
		t.Fatalf("ExtractPassword err = %v", err)
	}
	if got != "charset-secret" {
		t.Errorf("ExtractPassword = %q, want \"charset-secret\"", got)
	}
}

func TestDefaultHTTPExtractor_ExtractPassword_JSON_InvalidJSON_ReturnsError(t *testing.T) {
	ext := DefaultHTTPExtractor(Config{PasswordField: "password"})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("not valid json")))
	req.Header.Set("Content-Type", "application/json")

	got, err := ext.ExtractPassword(req)
	if err == nil {
		t.Error("ExtractPassword with invalid JSON: want non-nil error")
	}
	if got != "" {
		t.Errorf("ExtractPassword = %q, want \"\" when error", got)
	}
}

func TestDefaultHTTPExtractor_ExtractPassword_JSON_NilBody(t *testing.T) {
	ext := DefaultHTTPExtractor(Config{PasswordField: "password"})
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Body = nil
	req.Header.Set("Content-Type", "application/json")

	got, err := ext.ExtractPassword(req)
	if err != nil {
		t.Errorf("ExtractPassword(nil body) err = %v, want nil", err)
	}
	if got != "" {
		t.Errorf("ExtractPassword(nil body) = %q, want \"\"", got)
	}
}

func TestDefaultHTTPExtractor_ExtractPassword_JSON_FieldMissing(t *testing.T) {
	ext := DefaultHTTPExtractor(Config{PasswordField: "password"})
	body := []byte(`{"user":"john"}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	got, err := ext.ExtractPassword(req)
	if err != nil {
		t.Fatalf("ExtractPassword err = %v", err)
	}
	if got != "" {
		t.Errorf("ExtractPassword = %q, want \"\" when field missing", got)
	}
}

func TestDefaultHTTPExtractor_ExtractPassword_JSON_FieldNotString(t *testing.T) {
	ext := DefaultHTTPExtractor(Config{PasswordField: "password"})
	body := []byte(`{"password":123}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	got, err := ext.ExtractPassword(req)
	if err != nil {
		t.Fatalf("ExtractPassword err = %v", err)
	}
	if got != "" {
		t.Errorf("ExtractPassword = %q, want \"\" when field is not string", got)
	}
}

func TestDefaultHTTPExtractor_ExtractPassword_JSON_EmptyObject(t *testing.T) {
	ext := DefaultHTTPExtractor(Config{PasswordField: "password"})
	body := []byte(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	got, err := ext.ExtractPassword(req)
	if err != nil {
		t.Fatalf("ExtractPassword err = %v", err)
	}
	if got != "" {
		t.Errorf("ExtractPassword = %q, want \"\"", got)
	}
}

// Body is restored after read so the next handler can read it.
func TestDefaultHTTPExtractor_ExtractPassword_JSON_BodyRestored(t *testing.T) {
	ext := DefaultHTTPExtractor(Config{PasswordField: "password"})
	original := []byte(`{"password":"restored"}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(original))
	req.Header.Set("Content-Type", "application/json")

	_, _ = ext.ExtractPassword(req)
	if req.Body == nil {
		t.Fatal("Body is nil after ExtractPassword")
	}
	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading body after extract: %v", err)
	}
	if !bytes.Equal(restored, original) {
		t.Errorf("body after extract = %q, want %q", restored, original)
	}
}

// When Content-Type is form (not application/json), form extraction is used.
func TestDefaultHTTPExtractor_ExtractPassword_NoContentType_FormUsed(t *testing.T) {
	ext := DefaultHTTPExtractor(Config{PasswordField: "password"})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("password=formval"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	got, err := ext.ExtractPassword(req)
	if err != nil {
		t.Fatalf("ExtractPassword err = %v", err)
	}
	if got != "formval" {
		t.Errorf("ExtractPassword = %q, want \"formval\"", got)
	}
}
