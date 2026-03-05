// Package hibp provides a client for the Have I Been Pwned (HIBP) Pwned
// Passwords API using k-anonymity. Only the first 5 characters of the
// SHA-1 hash of the password are sent to the API; the full password and
// full hash are never transmitted or logged.
//
// See: https://haveibeenpwned.com/API/v3#PwnedPasswords
package hibp

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the HIBP Pwned Passwords API base URL.
	DefaultBaseURL = "https://api.pwnedpasswords.com"
	// PrefixLen is the number of hex characters (of the SHA-1 hash) sent to the API (k-anonymity).
	PrefixLen = 5
	// SHA1HexLen is the length of a full SHA-1 hash in hex (40 characters).
	SHA1HexLen = 40

	// DefaultMaxRetries is the default number of retry attempts for transient
	// failures and HTTP 429 rate-limit responses.
	DefaultMaxRetries = 3

	// DefaultRetryBaseDelay is the base delay for exponential back-off.
	// Actual delay for attempt n is: BaseDelay × 2^n + random jitter up to BaseDelay.
	DefaultRetryBaseDelay = 500 * time.Millisecond

	// maxRetryDelay caps the back-off to avoid excessively long waits.
	maxRetryDelay = 30 * time.Second
)

// Client calls the HIBP Pwned Passwords API. It is safe for concurrent use.
type Client struct {
	HTTPClient *http.Client
	BaseURL    string
	UserAgent  string
	Cache      Cache

	// MaxRetries is the number of retry attempts for transient network errors
	// and HTTP 429 (Too Many Requests) responses. A value of 0 disables
	// retries. Defaults to DefaultMaxRetries when NewClient is used.
	MaxRetries int

	// RetryBaseDelay is the base delay for exponential back-off between
	// retries. Each attempt waits BaseDelay×2^attempt plus random jitter
	// up to BaseDelay. Defaults to DefaultRetryBaseDelay when NewClient
	// is used. Capped at maxRetryDelay.
	RetryBaseDelay time.Duration

	// OfflineDB is an optional local breach database (e.g. a Bloom filter).
	// When provided, the Client will query this offline DB before making
	// network requests to the HIBP API.
	OfflineDB OfflineDB
}

// Cache allows optional caching of API responses (key = 5-char prefix, value = response body).
// Implementations must be safe for concurrent use.
type Cache interface {
	Get(key string) (value string, ok bool)
	Set(key string, value string, ttl time.Duration)
}

// NewClient returns a Client with default HTTP client, retry budget, and no cache.
func NewClient() *Client {
	return &Client{
		HTTPClient:     &http.Client{Timeout: 10 * time.Second},
		BaseURL:        DefaultBaseURL,
		UserAgent:      "passcheck-hibp/1.0",
		Cache:          nil,
		MaxRetries:     DefaultMaxRetries,
		RetryBaseDelay: DefaultRetryBaseDelay,
	}
}

// Check returns whether the password appears in the breach database and how many times.
// Only the first 5 characters of the SHA-1 hash are sent to the API (k-anonymity).
//
// Graceful degradation: The library level (passcheck) intentionally ignores errors
// returned by the HIBP checker. If an API or network error occurs, the check is
// skipped as if the password was not found in any breach.
func (c *Client) Check(password string) (breached bool, count int, err error) {
	return c.CheckContext(context.Background(), password)
}

// CheckContext is like Check but includes a context.Context for cancellation and timeouts.
func (c *Client) CheckContext(ctx context.Context, password string) (breached bool, count int, err error) {
	if password == "" {
		return false, 0, nil
	}
	hash := sha1Hash(password)
	return c.CheckHashContext(ctx, hash)
}

// CheckHash checks using a pre-computed 40-character lowercase SHA-1 hex string.
// If hash is not 40 hex chars, returns (false, 0, error).
// Only the first 5 characters of the hash are sent to the API.
func (c *Client) CheckHash(hash string) (breached bool, count int, err error) {
	return c.CheckHashContext(context.Background(), hash)
}

// CheckHashContext is like CheckHash but includes a context.Context.
func (c *Client) CheckHashContext(ctx context.Context, hash string) (breached bool, count int, err error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if len(hash) != SHA1HexLen || !isHex(hash) {
		return false, 0, fmt.Errorf("hibp: hash must be 40 hex characters, got %d", len(hash))
	}

	// 1. Check offline database first, if configured.
	if c.OfflineDB != nil {
		if present, offlineErr := c.OfflineDB.Has(ctx, hash); offlineErr == nil && present {
			// In offline mode (especially Bloom filters), we don't know the exact count,
			// but we know it's breached. We return count=1 to signify a breach.
			return true, 1, nil
		}
	}

	// 2. Fall back to online API check.
	prefix := hash[:PrefixLen]
	suffix := hash[PrefixLen:]

	body, err := c.fetchRange(ctx, prefix)
	if err != nil {
		return false, 0, err
	}

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		lineSuffix := strings.TrimSpace(strings.ToLower(line[:idx]))
		if lineSuffix != suffix {
			continue
		}
		countStr := strings.TrimSpace(line[idx+1:])
		n, parseErr := strconv.Atoi(countStr)
		if parseErr != nil {
			continue
		}
		return true, n, nil
	}
	return false, 0, nil
}

// fetchRange retrieves the HIBP range response for prefix, consulting the
// cache first and retrying on transient errors and HTTP 429 responses with
// exponential back-off and jitter.
func (c *Client) fetchRange(ctx context.Context, prefix string) (string, error) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if len(prefix) != PrefixLen {
		return "", fmt.Errorf("hibp: prefix must be %d hex characters", PrefixLen)
	}

	if c.Cache != nil {
		if v, ok := c.Cache.Get(prefix); ok {
			return v, nil
		}
	}

	maxAttempts := c.MaxRetries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(c.retryDelay(attempt - 1)):
			}
		}

		body, retryAfter, err := c.fetchRangeOnce(ctx, prefix)
		if err == nil {
			if c.Cache != nil {
				c.Cache.Set(prefix, body, DefaultCacheTTL)
			}
			return body, nil
		}

		lastErr = err

		// If the server sent a Retry-After header, honor it and then
		// continue to the next attempt (do not consume the back-off budget).
		if retryAfter > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(retryAfter):
			}
			attempt-- // do not consume budget
			continue
		}

		// Non-retryable errors (e.g. network errors, non-429 HTTP errors that
		// are unlikely to resolve on retry) are returned immediately.
		if !isRetryable(err) {
			return "", err
		}
	}

	return "", lastErr
}

// fetchRangeOnce performs a single HTTP GET for the given 5-char prefix.
// On HTTP 429 it returns (body="", retryAfter, err); on other non-200
// responses it returns the status error. retryAfter is zero unless the
// server included a Retry-After header.
func (c *Client) fetchRangeOnce(ctx context.Context, prefix string) (body string, retryAfter time.Duration, err error) {
	u, parseErr := url.Parse(c.BaseURL)
	if parseErr != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", 0, fmt.Errorf("hibp: invalid BaseURL scheme, must be http or https")
	}

	target := c.BaseURL + "/range/" + prefix
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return "", 0, err
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}

	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if resp.StatusCode == http.StatusTooManyRequests {
		ra := parseRetryAfter(resp.Header.Get("Retry-After"))
		return "", ra, fmt.Errorf("hibp: API returned %s", resp.Status)
	}

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("hibp: API returned %s", resp.Status)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}
	return string(b), 0, nil
}

// retryDelay returns the back-off duration for the given retry index (0-based).
// delay = min(BaseDelay×2^attempt, maxRetryDelay) + jitter(0..BaseDelay).
func (c *Client) retryDelay(attempt int) time.Duration {
	base := c.RetryBaseDelay
	if base <= 0 {
		base = DefaultRetryBaseDelay
	}
	exp := time.Duration(math.Pow(2, float64(attempt))) * base
	if exp > maxRetryDelay {
		exp = maxRetryDelay
	}
	return exp + jitter(base)
}

// jitter returns a random duration in [0, maxDur).
func jitter(maxDur time.Duration) time.Duration {
	if maxDur <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return time.Duration(binary.LittleEndian.Uint64(b[:]) % uint64(maxDur))
}

// parseRetryAfter parses the Retry-After header value. It supports the
// delay-seconds form (e.g. "30") and the HTTP-date form. Returns 0 on
// any parse failure so the caller falls back to normal back-off.
func parseRetryAfter(header string) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0
	}
	// Delay-seconds form.
	if secs, err := strconv.Atoi(header); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	// HTTP-date form.
	if t, err := http.ParseTime(header); err == nil {
		d := time.Until(t)
		if d > 0 {
			return d
		}
	}
	return 0
}

// isRetryable returns true for errors that are worth retrying (rate-limit
// and transient network issues).
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "429") || strings.Contains(s, "Too Many Requests")
}

func sha1Hash(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func isHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}
