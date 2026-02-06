// Package middleware provides HTTP middleware for password strength validation
// using passcheck. It supports net/http and optional adapters for Echo, Gin,
// Fiber, and Chi. Use [Config] to set minimum score, password extraction, and
// failure handling.
//
// # net/http (zero additional dependencies)
//
//	http.Handle("/register", middleware.HTTP(middleware.Config{
//	    MinScore:      60,
//	    PasswordField: "password",
//	}, registrationHandler))
//
// # Chi (net/http compatible)
//
//	r.Use(middleware.Chi(middleware.Config{MinScore: 60}))
//
// # Echo, Gin, Fiber (optional)
//
// Adapters are in build-tagged files. To use them, add the framework dependency
// and build with the tag, for example:
//
//	go get github.com/labstack/echo/v4
//	go build -tags=echo ./...
//
// Then use middleware.Echo(cfg), middleware.Gin(cfg), or middleware.Fiber(cfg).
package middleware

import (
	"github.com/rafaelsanzio/passcheck"
)

// Config configures the password validation middleware.
//
// Use [DefaultConfig] for sensible defaults, then override as needed.
type Config struct {
	// MinScore is the minimum passcheck score (0–100) required to allow the request.
	// If the password scores below this, the middleware rejects with HTTP 400.
	// Default: 60 (typically "Okay" or stronger).
	MinScore int

	// PasswordField is the name of the form or JSON field containing the password.
	// Used by the default extractor for form and JSON body. Default: "password".
	PasswordField string

	// OnFailure is an optional hook called when the password fails the policy.
	// It receives the list of issues; the middleware still writes the 400 response.
	// Use for logging, metrics, or custom side effects. Default: nil.
	OnFailure func(issues []passcheck.Issue) error

	// SkipIfEmpty, when true, skips validation when the extracted password is empty
	// and calls the next handler (useful for optional password fields). When false,
	// an empty password is treated as a failed check. Default: false.
	SkipIfEmpty bool

	// PasscheckConfig is the configuration passed to passcheck.CheckWithConfig.
	// If zero, [passcheck.DefaultConfig] is used.
	PasscheckConfig passcheck.Config
}

// DefaultConfig returns a config with recommended defaults.
func DefaultConfig() Config {
	return Config{
		MinScore:        60,
		PasswordField:   "password",
		OnFailure:       nil,
		SkipIfEmpty:     false,
		PasscheckConfig: passcheck.DefaultConfig(),
	}
}

// Extractor extracts a password from an incoming request.
// The default HTTP middleware uses an extractor that checks form values
// and JSON body (see [DefaultHTTPExtractor]). Framework adapters use
// their own extraction logic.
type Extractor interface {
	// ExtractPassword returns the password from the request, or ("", nil) if none.
	// The request type is framework-specific (*http.Request for net/http).
	ExtractPassword(req interface{}) (string, error)
}
