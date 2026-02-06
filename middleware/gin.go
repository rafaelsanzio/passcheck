//go:build gin

package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rafaelsanzio/passcheck"
)

// Gin returns a Gin middleware that validates the request password.
// Build with -tags=gin to enable. Password is extracted from form or JSON body
// using Config.PasswordField (default "password").
//
//	r.POST("/register", middleware.Gin(middleware.Config{MinScore: 60}), registerHandler)
func Gin(cfg Config) gin.HandlerFunc {
	def := DefaultConfig()
	if cfg.PasswordField == "" {
		cfg.PasswordField = def.PasswordField
	}
	if cfg.MinScore == 0 {
		cfg.MinScore = def.MinScore
	}
	extractor := DefaultHTTPExtractor(cfg)
	return func(c *gin.Context) {
		password, err := extractor.ExtractPassword(c.Request)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			c.Abort()
			return
		}
		if password == "" {
			if cfg.SkipIfEmpty {
				c.Next()
				return
			}
			c.JSON(http.StatusBadRequest, weakPasswordBody{
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": "configuration error"})
			c.Abort()
			return
		}
		if result.Score < cfg.MinScore {
			if cfg.OnFailure != nil {
				_ = cfg.OnFailure(result.Issues)
			}
			c.JSON(http.StatusBadRequest, weakPasswordBody{
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
