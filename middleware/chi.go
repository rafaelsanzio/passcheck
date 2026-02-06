package middleware

import "net/http"

// Chi returns a Chi-compatible middleware that validates the request password.
// Chi uses standard net/http, so this is a thin wrapper around [HTTP]:
//
//	r := chi.NewRouter()
//	r.Use(middleware.Chi(middleware.Config{MinScore: 60}))
//	r.Post("/register", registerHandler)
func Chi(cfg Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return HTTP(cfg, next)
	}
}
