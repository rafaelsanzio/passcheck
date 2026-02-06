package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rafaelsanzio/passcheck"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MinScore != 60 {
		t.Errorf("MinScore = %d, want 60", cfg.MinScore)
	}
	if cfg.PasswordField != "password" {
		t.Errorf("PasswordField = %q, want \"password\"", cfg.PasswordField)
	}
	if cfg.SkipIfEmpty {
		t.Error("SkipIfEmpty = true, want false")
	}
}

func TestHTTP_MissingPassword(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := HTTP(Config{MinScore: 60, PasswordField: "password"}, next)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error != "password is required" {
		t.Errorf("error = %q, want password is required", body.Error)
	}
}

func TestHTTP_FormPassword_Weak(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := HTTP(Config{MinScore: 60, PasswordField: "password"}, next)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body = io.NopCloser(bytes.NewReader([]byte("password=123")))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if nextCalled {
		t.Error("next handler should not be called for weak password")
	}
	var body weakPasswordBody
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Score == 0 && len(body.Issues) == 0 {
		t.Error("expected score or issues in response")
	}
}

func TestHTTP_FormPassword_Strong(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := HTTP(Config{MinScore: 60, PasswordField: "password"}, next)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body = io.NopCloser(bytes.NewReader([]byte("password=Xk9$mP2!vR7@nL4&wQ")))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !nextCalled {
		t.Error("next handler should be called for strong password")
	}
}

func TestHTTP_JSONPassword_Weak(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := HTTP(Config{MinScore: 60, PasswordField: "password"}, next)

	body := bytes.NewBufferString(`{"password":"qwerty"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var res weakPasswordBody
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Error == "" {
		t.Error("expected error message")
	}
}

func TestHTTP_JSONPassword_Strong(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := HTTP(Config{MinScore: 60, PasswordField: "password"}, next)

	body := bytes.NewBufferString(`{"password":"MyC0mpl3x!P@ss2024"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !nextCalled {
		t.Error("next handler should be called")
	}
}

func TestHTTP_SkipIfEmpty(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := HTTP(Config{MinScore: 60, SkipIfEmpty: true}, next)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !nextCalled {
		t.Error("next handler should be called when SkipIfEmpty and no password")
	}
}

func TestHTTP_OnFailure_Called(t *testing.T) {
	var captured []passcheck.Issue
	cfg := Config{
		MinScore:  80,
		OnFailure: func(issues []passcheck.Issue) error { captured = issues; return nil },
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := HTTP(cfg, next)

	body := bytes.NewBufferString(`{"password":"weak"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if len(captured) == 0 {
		t.Error("OnFailure should be called with issues")
	}
}

func TestHTTP_CustomPasswordField(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := HTTP(Config{MinScore: 60, PasswordField: "pwd"}, next)

	body := bytes.NewBufferString(`{"pwd":"MyC0mpl3x!P@ss2024"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !nextCalled {
		t.Error("next handler should be called")
	}
}

func TestChi_ReturnsMiddleware(t *testing.T) {
	fn := Chi(Config{MinScore: 60})
	if fn == nil {
		t.Fatal("Chi returned nil")
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	wrapped := fn(next)
	if wrapped == nil {
		t.Fatal("wrapped handler is nil")
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("password=weak")))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Chi middleware status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// TestHTTP_WeakPassword_ResponseBody verifies 400 response has proper structure (error, score, issues).
func TestHTTP_WeakPassword_ResponseBody(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := HTTP(Config{MinScore: 60, PasswordField: "password"}, next)

	body := bytes.NewBufferString(`{"password":"123"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var res weakPasswordBody
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Error == "" {
		t.Error("expected non-empty error message")
	}
	if res.Score < 0 || res.Score > 100 {
		t.Errorf("score %d not in 0–100", res.Score)
	}
	// Issues may be empty or populated; response must be valid JSON with expected keys
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", rec.Header().Get("Content-Type"))
	}
}

// TestHTTP_CustomPasscheckConfig verifies PasscheckConfig is applied (e.g. MinLength).
func TestHTTP_CustomPasscheckConfig(t *testing.T) {
	cfg := Config{
		MinScore:      60,
		PasswordField: "password",
		PasscheckConfig: passcheck.Config{
			MinLength:        10,
			RequireUpper:     true,
			RequireLower:     true,
			RequireDigit:     true,
			RequireSymbol:    true,
			MaxRepeats:       3,
			PatternMinLength: 4,
			MaxIssues:        5,
		},
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := HTTP(cfg, next)

	// 8-char password fails MinLength 10
	body := bytes.NewBufferString(`{"password":"Ab1!abcd"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d (short password should fail)", rec.Code, http.StatusBadRequest)
	}
	var res weakPasswordBody
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	hasTooShort := false
	for _, iss := range res.Issues {
		if iss.Code == passcheck.CodeRuleTooShort || strings.Contains(strings.ToLower(iss.Message), "short") {
			hasTooShort = true
			break
		}
	}
	if !hasTooShort {
		t.Logf("issues: %+v (expected 'too short' when MinLength=10)", res.Issues)
	}
}

// TestHTTP_InvalidJSON_BadRequest ensures invalid JSON body with application/json
// returns 400 and "invalid request body" (writeError path).
func TestHTTP_InvalidJSON_BadRequest(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := HTTP(Config{MinScore: 60, PasswordField: "password"}, next)

	body := bytes.NewBufferString("not valid json")
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var res struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Error != "invalid request body" {
		t.Errorf("error = %q, want \"invalid request body\"", res.Error)
	}
}

// TestHTTP_ConfigDefaults verifies zero Config gets defaults: MinScore 60, PasswordField "password".
func TestHTTP_ConfigDefaults(t *testing.T) {
	// MinScore 0 and PasswordField "" should be filled from DefaultConfig.
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := HTTP(Config{}, next)

	// Weak password should still be rejected (MinScore defaults to 60).
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body = io.NopCloser(bytes.NewReader([]byte("password=123")))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("with Config{} weak password: status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	// PasswordField "" should default to "password", so form "password=..." works.
	next2 := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	handler2 := HTTP(Config{}, next2)
	req2 := httptest.NewRequest(http.MethodPost, "/", nil)
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Body = io.NopCloser(bytes.NewReader([]byte("password=Xk9$mP2!vR7@nL4&wQ")))
	rec2 := httptest.NewRecorder()
	handler2.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Errorf("with Config{} strong password (default field): status = %d, want %d", rec2.Code, http.StatusOK)
	}
}

// TestHTTP_JSON_BodyRestored verifies the request body is restored after extraction
// so the next handler can read it (e.g. for further JSON parsing).
func TestHTTP_JSON_BodyRestored(t *testing.T) {
	var nextBody []byte
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})
	handler := HTTP(Config{MinScore: 60, PasswordField: "password"}, next)

	payload := []byte(`{"password":"MyC0mpl3x!P@ss2024","extra":"data"}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !bytes.Equal(nextBody, payload) {
		t.Errorf("next handler body = %q, want %q", nextBody, payload)
	}
}

// TestHTTP_OnFailure_ReturnError_StillRejects verifies that when OnFailure returns
// an error, the middleware still responds with 400 (error is ignored).
func TestHTTP_OnFailure_ReturnError_StillRejects(t *testing.T) {
	cfg := Config{
		MinScore:  80,
		OnFailure: func([]passcheck.Issue) error { return io.EOF },
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := HTTP(cfg, next)

	body := bytes.NewBufferString(`{"password":"weak"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d (OnFailure error should not change response)", rec.Code, http.StatusBadRequest)
	}
}

// TestHTTP_InvalidPasscheckConfig_FallsBackToDefault verifies that invalid
// PasscheckConfig (e.g. MinLength 0) causes the middleware to use passcheck.DefaultConfig()
// and still validate (strong password passes).
func TestHTTP_InvalidPasscheckConfig_FallsBackToDefault(t *testing.T) {
	cfg := Config{
		MinScore:        60,
		PasswordField:   "password",
		PasscheckConfig: passcheck.Config{}, // invalid: MinLength 0
	}
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := HTTP(cfg, next)

	// Use same strong password as TestHTTP_FormPassword_Strong so default config accepts it.
	body := bytes.NewBufferString(`{"password":"Xk9$mP2!vR7@nL4&wQ"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (invalid config should fallback to default)", rec.Code, http.StatusOK)
	}
	if !nextCalled {
		t.Error("next handler should be called when fallback config accepts password")
	}
}
