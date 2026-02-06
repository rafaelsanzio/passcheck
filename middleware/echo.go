//go:build echo

package middleware

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/rafaelsanzio/passcheck"
)

// Echo returns an Echo middleware that validates the request password.
// Build with -tags=echo to enable. Password is extracted from form or JSON body
// using Config.PasswordField (default "password").
//
//	e.POST("/register", handler, middleware.Echo(middleware.Config{MinScore: 60}))
func Echo(cfg Config) echo.MiddlewareFunc {
	def := DefaultConfig()
	if cfg.PasswordField == "" {
		cfg.PasswordField = def.PasswordField
	}
	if cfg.MinScore == 0 {
		cfg.MinScore = def.MinScore
	}
	extractor := DefaultHTTPExtractor(cfg)
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
				return c.JSON(http.StatusBadRequest, weakPasswordBody{
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
				return c.JSON(http.StatusBadRequest, weakPasswordBody{
					Error:  "password does not meet strength requirements",
					Score:  result.Score,
					Issues: result.Issues,
				})
			}
			return next(c)
		}
	}
}
