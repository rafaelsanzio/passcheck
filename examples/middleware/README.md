# Middleware Example

Simple demonstration of the passcheck HTTP middleware for protecting password-related endpoints.

## Run

```bash
go run ./examples/middleware
```

Server starts on `:8080` with:

- **POST /register** — Validates password strength; rejects weak passwords with 400
- **GET /health** — Health check

## Test

```bash
# Weak password (rejected with 400)
curl -X POST http://localhost:8080/register \
  -H 'Content-Type: application/json' \
  -d '{"password":"weak123"}'

# Strong password (accepted with 201)
curl -X POST http://localhost:8080/register \
  -H 'Content-Type: application/json' \
  -d '{"password":"MyC0mpl3x!P@ssw0rd2024"}'

# Form data also works
curl -X POST http://localhost:8080/register \
  -d 'password=MyC0mpl3x!P@ssw0rd2024'
```

## What it demonstrates

- **Zero dependencies** — Uses only net/http from the standard library
- **Simple configuration** — MinScore, PasswordField, OnFailure hook
- **Automatic extraction** — Supports both JSON (`{"password":"..."}`) and form data (`password=...`)
- **Clear error responses** — Weak passwords get 400 with error, score, and issues

## Use with other frameworks

The middleware package supports Chi, Echo, Gin, and Fiber:

```go
// Chi (net/http compatible)
r.Use(middleware.Chi(middleware.Config{MinScore: 60}))

// Echo (requires go get + build tag)
e.POST("/register", handler, middleware.Echo(cfg))

// Gin
r.POST("/register", middleware.Gin(cfg), handler)

// Fiber
app.Post("/register", middleware.Fiber(cfg), handler)
```

See `middleware/` package docs for details on optional framework adapters.
