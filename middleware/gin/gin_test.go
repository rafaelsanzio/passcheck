package passcheckgin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	ginfx "github.com/gin-gonic/gin"
	"github.com/rafaelsanzio/passcheck/middleware"
)

func init() { ginfx.SetMode(ginfx.TestMode) }

// testResponseBody mirrors the JSON shape returned by the middleware on rejection.
type testResponseBody struct {
	Error string `json:"error"`
	Score int    `json:"score"`
}

func TestGin_WeakPassword_Returns400(t *testing.T) {
	r := ginfx.New()
	r.POST("/register", Gin(middleware.Config{MinScore: 60}), func(c *ginfx.Context) {
		c.String(http.StatusOK, "ok")
	})

	body := bytes.NewReader([]byte(`{"password":"123"}`))
	req := httptest.NewRequest(http.MethodPost, "/register", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var res testResponseBody
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Error == "" {
		t.Error("expected error message")
	}
}

func TestGin_StrongPassword_CallsNext(t *testing.T) {
	r := ginfx.New()
	nextCalled := false
	r.POST("/register", Gin(middleware.Config{MinScore: 60}), func(c *ginfx.Context) {
		nextCalled = true
		c.String(http.StatusOK, "registered")
	})

	body := bytes.NewReader([]byte(`{"password":"MyC0mpl3x!P@ss2024"}`))
	req := httptest.NewRequest(http.MethodPost, "/register", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !nextCalled {
		t.Error("next handler should be called")
	}
}
