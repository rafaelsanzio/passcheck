package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestChi_WeakPassword_Rejected(t *testing.T) {
	fn := Chi(Config{MinScore: 60, PasswordField: "password"})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := fn(next)

	body := bytes.NewBufferString(`{"password":"123"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Chi weak password: status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var res weakPasswordBody
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestChi_StrongPassword_Accepted(t *testing.T) {
	nextCalled := false
	fn := Chi(Config{MinScore: 60, PasswordField: "password"})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := fn(next)

	body := bytes.NewBufferString(`{"password":"MyC0mpl3x!P@ss2024"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Chi strong password: status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !nextCalled {
		t.Error("next handler should be called for strong password")
	}
}

func TestChi_SkipIfEmpty(t *testing.T) {
	nextCalled := false
	fn := Chi(Config{MinScore: 60, SkipIfEmpty: true})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := fn(next)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Chi skip-if-empty: status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !nextCalled {
		t.Error("next handler should be called when SkipIfEmpty and no password")
	}
}

func TestChi_MissingPassword_Rejected(t *testing.T) {
	fn := Chi(Config{MinScore: 60, PasswordField: "password"})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := fn(next)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Chi missing password: status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
