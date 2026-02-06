//go:build gin

package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

func TestGin_WeakPassword_Returns400(t *testing.T) {
	r := gin.New()
	r.POST("/register", Gin(Config{MinScore: 60}), func(c *gin.Context) {
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
	var res weakPasswordBody
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Error == "" {
		t.Error("expected error message")
	}
}

func TestGin_StrongPassword_CallsNext(t *testing.T) {
	r := gin.New()
	nextCalled := false
	r.POST("/register", Gin(Config{MinScore: 60}), func(c *gin.Context) {
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
