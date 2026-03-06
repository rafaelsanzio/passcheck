// Package passcheckfiber provides a Fiber middleware adapter for passcheck.
//
// Import this package to add password strength validation to a Fiber app:
//
//	import passcheckfiber "github.com/rafaelsanzio/passcheck/middleware/fiber"
//
//	app.Post("/register",
//	    passcheckfiber.Fiber(middleware.Config{MinScore: 60}),
//	    registerHandler,
//	)
//
// The middleware reads the password from the JSON body or form field named
// by [middleware.Config.PasswordField] (default "password") and rejects
// requests with HTTP 400 when the score is below [middleware.Config.MinScore].
//
// Note: Fiber uses fasthttp internally, so password extraction is handled by
// a dedicated extractor rather than the net/http [middleware.DefaultHTTPExtractor].
package passcheckfiber

import (
	"encoding/json"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/rafaelsanzio/passcheck"
	"github.com/rafaelsanzio/passcheck/middleware"
)

// responseBody is the JSON body returned on a rejected request.
type responseBody struct {
	Error  string            `json:"error"`
	Score  int               `json:"score"`
	Issues []passcheck.Issue `json:"issues"`
}

// Fiber returns a Fiber middleware that validates the request password using passcheck.
// Password is extracted from the JSON body or form field (keyed by
// [middleware.Config.PasswordField]).
//
// If the password scores below [middleware.Config.MinScore], the middleware
// responds with HTTP 400 JSON and the handler chain is stopped.
//
//	app.Post("/register", passcheckfiber.Fiber(middleware.Config{MinScore: 60}), registerHandler)
func Fiber(cfg middleware.Config) fiber.Handler {
	def := middleware.DefaultConfig()
	if cfg.PasswordField == "" {
		cfg.PasswordField = def.PasswordField
	}
	if cfg.MinScore == 0 {
		cfg.MinScore = def.MinScore
	}
	return func(c *fiber.Ctx) error {
		password, err := extractPassword(c, cfg.PasswordField)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
		}
		if password == "" {
			if cfg.SkipIfEmpty {
				return c.Next()
			}
			return c.Status(fiber.StatusBadRequest).JSON(responseBody{
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
			return c.Status(fiber.StatusBadRequest).JSON(responseBody{
				Error:  "password does not meet strength requirements",
				Score:  result.Score,
				Issues: result.Issues,
			})
		}
		return c.Next()
	}
}

// extractPassword reads the password field from a Fiber context. Fiber uses
// fasthttp (not net/http) so the standard DefaultHTTPExtractor cannot be reused.
func extractPassword(c *fiber.Ctx, field string) (string, error) {
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
