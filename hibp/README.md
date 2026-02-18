# hibp — Have I Been Pwned API client

Optional client for the [Have I Been Pwned](https://haveibeenpwned.com/) Pwned Passwords API. Use it with passcheck to flag passwords that have appeared in data breaches.

## Privacy (k-anonymity)

Only the **first 5 characters** of the SHA-1 hash of the password are sent to the API. The full password and full hash are never transmitted or logged.

## Usage

```go
import (
    "github.com/rafaelsanzio/passcheck"
    "github.com/rafaelsanzio/passcheck/hibp"
)

cfg := passcheck.DefaultConfig()
client := hibp.NewClient()
client.Cache = hibp.NewMemoryCacheWithTTL(256, hibp.DefaultCacheTTL)
cfg.HIBPChecker = client

result, _ := passcheck.CheckWithConfig(password, cfg)
```

See [examples/hibp](../examples/hibp/) for a runnable example.

## API

- **NewClient()** — returns a client with default HTTP client and no cache
- **Client.Check(password)** — returns `(breached bool, count int, err error)`
- **Client.CheckHash(sha1Hex)** — same, using a 40-char SHA-1 hex string
- **NewMemoryCache**, **NewMemoryCacheWithTTL** — optional in-memory cache with TTL
- **MockClient** — for tests

On network or API errors, passcheck skips the breach check (graceful degradation).
