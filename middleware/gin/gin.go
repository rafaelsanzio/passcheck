// Package passcheckgin provides a Gin middleware adapter for passcheck.
//
// Import this package to add password strength validation to a Gin router:
//
//	import passcheckgin "github.com/rafaelsanzio/passcheck/middleware/gin"
//
//	r.POST("/register",
//	    passcheckgin.Gin(middleware.Config{MinScore: 60}),
//	    registerHandler,
//	)
//
// The middleware reads the password from the JSON body or form field named
// by [middleware.Config.PasswordField] (default "password") and rejects
// requests with HTTP 400 when the score is below [middleware.Config.MinScore].
package passcheckgin

import (
	"net/http"

	ginfx "github.com/gin-gonic/gin"
	"github.com/rafaelsanzio/passcheck"
	"github.com/rafaelsanzio/passcheck/middleware"
)

// responseBody is the JSON body returned on a rejected request.
type responseBody struct {
	Error  string            `json:"error"`
	Score  int               `json:"score"`
	Issues []passcheck.Issue `json:"issues"`
}

// Gin returns a Gin middleware that validates the request password using passcheck.
// Password is extracted from the JSON body or form field using the default
// [middleware.DefaultHTTPExtractor] (keyed by [middleware.Config.PasswordField]).
//
// If the password scores below [middleware.Config.MinScore], the middleware
// responds with HTTP 400 JSON and calls c.Abort() so no further handlers run.
//
//	r.POST("/register", passcheckgin.Gin(middleware.Config{MinScore: 60}), registerHandler)
func Gin(cfg middleware.Config) ginfx.HandlerFunc {
	def := middleware.DefaultConfig()
	if cfg.PasswordField == "" {
		cfg.PasswordField = def.PasswordField
	}
	if cfg.MinScore == 0 {
		cfg.MinScore = def.MinScore
	}
	extractor := middleware.DefaultHTTPExtractor(cfg)
	return func(c *ginfx.Context) {
		password, err := extractor.ExtractPassword(c.Request)
		if err != nil {
			c.JSON(http.StatusBadRequest, ginfx.H{"error": "invalid request body"})
			c.Abort()
			return
		}
		if password == "" {
			if cfg.SkipIfEmpty {
				c.Next()
				return
			}
			c.JSON(http.StatusBadRequest, responseBody{
				Error:  "password is required",
				Score:  0,
				Issues: nil,
			})
			c.Abort()
			return
		}
		pc := cfg.PasscheckConfig
		if err := pc.Validate(); err != nil {
			pc = passcheck.DefaultConfig()
		}
		result, err := passcheck.CheckWithConfig(password, pc)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ginfx.H{"error": "configuration error"})
			c.Abort()
			return
		}
		if result.Score < cfg.MinScore {
			if cfg.OnFailure != nil {
				_ = cfg.OnFailure(result.Issues)
			}
			c.JSON(http.StatusBadRequest, responseBody{
				Error:  "password does not meet strength requirements",
				Score:  result.Score,
				Issues: result.Issues,
			})
			c.Abort()
			return
		}
		c.Next()
	}
}
