# HIBP integration example

This example shows how to check passwords against the [Have I Been Pwned](https://haveibeenpwned.com/) (HIBP) breach database when using passcheck.

## Privacy (k-anonymity)

Only the **first 5 characters** of the SHA-1 hash of the password are sent to the API. The full password and full hash are never transmitted or logged.

## Run

```bash
go run .
```

Requires network access to `api.pwnedpasswords.com`. The example uses an optional in-memory cache to reduce API calls.

## Usage in your app

```go
cfg := passcheck.DefaultConfig()
client := hibp.NewClient()
client.Cache = hibp.NewMemoryCacheWithTTL(256, hibp.DefaultCacheTTL)
cfg.HIBPChecker = client
cfg.HIBPMinOccurrences = 1

result, _ := passcheck.CheckWithConfig(password, cfg)
for _, iss := range result.Issues {
    if iss.Code == passcheck.CodeHIBPBreached {
        // Password was found in a breach
    }
}
```

On network or API errors, passcheck skips the HIBP check (graceful degradation) and still returns the rest of the result.
