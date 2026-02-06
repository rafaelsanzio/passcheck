//go:build echo

package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestEcho_WeakPassword_Returns400(t *testing.T) {
	e := echo.New()
	e.POST("/register", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	}, Echo(Config{MinScore: 60}))

	body := bytes.NewReader([]byte(`{"password":"123"}`))
	req := httptest.NewRequest(http.MethodPost, "/register", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

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

func TestEcho_StrongPassword_CallsNext(t *testing.T) {
	e := echo.New()
	nextCalled := false
	e.POST("/register", func(c echo.Context) error {
		nextCalled = true
		return c.String(http.StatusOK, "registered")
	}, Echo(Config{MinScore: 60}))

	body := bytes.NewReader([]byte(`{"password":"MyC0mpl3x!P@ss2024"}`))
	req := httptest.NewRequest(http.MethodPost, "/register", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !nextCalled {
		t.Error("next handler should be called")
	}
}
