// Package passcheckecho provides an Echo middleware adapter for passcheck.
//
// Import this package to add password strength validation to an Echo server:
//
//	import passcheckecho "github.com/rafaelsanzio/passcheck/middleware/echo"
//
//	e.POST("/register", handler, passcheckecho.Echo(middleware.Config{MinScore: 60}))
//
// The middleware reads the password from the JSON body or form field named
// by [middleware.Config.PasswordField] (default "password") and rejects
// requests with HTTP 400 when the score is below [middleware.Config.MinScore].
package passcheckecho

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/rafaelsanzio/passcheck"
	"github.com/rafaelsanzio/passcheck/middleware"
)

// responseBody is the JSON body returned on a rejected request.
type responseBody struct {
	Error  string            `json:"error"`
	Score  int               `json:"score"`
	Issues []passcheck.Issue `json:"issues"`
}

// Echo returns an Echo middleware that validates the request password using passcheck.
// Password is extracted from the JSON body or form field using the default
// [middleware.DefaultHTTPExtractor] (keyed by [middleware.Config.PasswordField]).
//
// If the password scores below [middleware.Config.MinScore], the middleware
// responds with HTTP 400 JSON and the request chain is stopped.
//
//	e.POST("/register", handler, passcheckecho.Echo(middleware.Config{MinScore: 60}))
func Echo(cfg middleware.Config) echo.MiddlewareFunc {
	def := middleware.DefaultConfig()
	if cfg.PasswordField == "" {
		cfg.PasswordField = def.PasswordField
	}
	if cfg.MinScore == 0 {
		cfg.MinScore = def.MinScore
	}
	extractor := middleware.DefaultHTTPExtractor(cfg)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			password, err := extractor.ExtractPassword(c.Request())
			if err != nil {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			}
			if password == "" {
				if cfg.SkipIfEmpty {
					return next(c)
				}
				return c.JSON(http.StatusBadRequest, responseBody{
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
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "configuration error"})
			}
			if result.Score < cfg.MinScore {
				if cfg.OnFailure != nil {
					_ = cfg.OnFailure(result.Issues)
				}
				return c.JSON(http.StatusBadRequest, responseBody{
					Error:  "password does not meet strength requirements",
					Score:  result.Score,
					Issues: result.Issues,
				})
			}
			return next(c)
		}
	}
}
