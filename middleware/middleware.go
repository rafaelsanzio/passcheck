// Package middleware provides HTTP middleware for password strength validation
// using passcheck. It supports net/http and Chi out of the box (zero additional
// dependencies). Framework-specific adapters for Echo, Gin, and Fiber live in
// their own submodules so downstream projects only pull in the framework they
// actually use.
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
// # Echo, Gin, Fiber (separate submodules)
//
//	go get github.com/rafaelsanzio/passcheck/middleware/echo
//	go get github.com/rafaelsanzio/passcheck/middleware/gin
//	go get github.com/rafaelsanzio/passcheck/middleware/fiber
//
// Each submodule exports a single constructor (Echo, Gin, Fiber) that accepts
// this package's [Config] type.
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
