//go:build fiber

package middleware

import (
	"encoding/json"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/rafaelsanzio/passcheck"
)

// Fiber returns a Fiber middleware that validates the request password.
// Build with -tags=fiber to enable. Password is extracted from form or JSON body
// using Config.PasswordField (default "password").
//
//	app.Post("/register", middleware.Fiber(middleware.Config{MinScore: 60}), registerHandler)
func Fiber(cfg Config) fiber.Handler {
	def := DefaultConfig()
	if cfg.PasswordField == "" {
		cfg.PasswordField = def.PasswordField
	}
	if cfg.MinScore == 0 {
		cfg.MinScore = def.MinScore
	}
	return func(c *fiber.Ctx) error {
		password, err := extractPasswordFiber(c, cfg.PasswordField)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
		}
		if password == "" {
			if cfg.SkipIfEmpty {
				return c.Next()
			}
			return c.Status(fiber.StatusBadRequest).JSON(weakPasswordBody{
				Error:  "password is required",
				Score:  0,
				Issues: nil,
			})
		}
		pc := cfg.PasscheckConfig
		if err := pc.Validate(); err != nil {
			pc = passcheck.DefaultConfig()
		}
		result, err := passcheck.CheckWithConfig(password, pc)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "configuration error"})
		}
		if result.Score < cfg.MinScore {
			if cfg.OnFailure != nil {
				_ = cfg.OnFailure(result.Issues)
			}
			return c.Status(fiber.StatusBadRequest).JSON(weakPasswordBody{
				Error:  "password does not meet strength requirements",
				Score:  result.Score,
				Issues: result.Issues,
			})
		}
		return c.Next()
	}
}

func extractPasswordFiber(c *fiber.Ctx, field string) (string, error) {
	ct := string(c.Request().Header.ContentType())
	if strings.HasPrefix(strings.TrimSpace(ct), "application/json") {
		var raw map[string]interface{}
		if err := json.Unmarshal(c.Body(), &raw); err != nil {
			return "", nil
		}
		if v, ok := raw[field]; ok {
			if s, ok := v.(string); ok {
				return s, nil
			}
		}
		return "", nil
	}
	return c.FormValue(field), nil
}
