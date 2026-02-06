//go:build fiber

package middleware

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestFiber_WeakPassword_Returns400(t *testing.T) {
	app := fiber.New()
	app.Post("/register", Fiber(Config{MinScore: 60}), func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	body := bytes.NewReader([]byte(`{"password":"123"}`))
	req := httptest.NewRequest("POST", "/register", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != fiber.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, fiber.StatusBadRequest)
	}
	var res weakPasswordBody
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Error == "" {
		t.Error("expected error message")
	}
}

func TestFiber_StrongPassword_CallsNext(t *testing.T) {
	app := fiber.New()
	nextCalled := false
	app.Post("/register", Fiber(Config{MinScore: 60}), func(c *fiber.Ctx) error {
		nextCalled = true
		return c.SendString("registered")
	})

	body := bytes.NewReader([]byte(`{"password":"MyC0mpl3x!P@ss2024"}`))
	req := httptest.NewRequest("POST", "/register", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, fiber.StatusOK)
	}
	if !nextCalled {
		t.Error("next handler should be called")
	}
}
