// Package hibp provides a client for the Have I Been Pwned (HIBP) Pwned
// Passwords API using k-anonymity. Only the first 5 characters of the
// SHA-1 hash of the password are sent to the API; the full password and
// full hash are never transmitted or logged.
//
// See: https://haveibeenpwned.com/API/v3#PwnedPasswords
package hibp

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
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
)

// Client calls the HIBP Pwned Passwords API. It is safe for concurrent use.
type Client struct {
	HTTPClient *http.Client
	BaseURL    string
	UserAgent  string
	Cache      Cache
}

// Cache allows optional caching of API responses (key = 5-char prefix, value = response body).
// Implementations must be safe for concurrent use.
type Cache interface {
	Get(key string) (value string, ok bool)
	Set(key string, value string, ttl time.Duration)
}

// NewClient returns a Client with default HTTP client and no cache.
func NewClient() *Client {
	return &Client{
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		BaseURL:    DefaultBaseURL,
		UserAgent:  "passcheck-hibp/1.0",
		Cache:      nil,
	}
}

// Check returns whether the password appears in the breach database and how many times.
// Only the first 5 characters of the SHA-1 hash are sent to the API (k-anonymity).
//
// Graceful degradation: The library level (passcheck) intentionally ignores errors
// returned by the HIBP checker. If an API or network error occurs, the check is
// skipped as if the password was not found in any breach.
func (c *Client) Check(password string) (breached bool, count int, err error) {

	if password == "" {
		return false, 0, nil
	}
	hash := sha1Hash(password)
	return c.CheckHash(hash)
}

// CheckHash checks using a pre-computed 40-character lowercase SHA-1 hex string.
// If hash is not 40 hex chars, returns (false, 0, error).
// Only the first 5 characters of the hash are sent to the API.
func (c *Client) CheckHash(hash string) (breached bool, count int, err error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if len(hash) != SHA1HexLen || !isHex(hash) {
		return false, 0, fmt.Errorf("hibp: hash must be 40 hex characters, got %d", len(hash))
	}
	prefix := hash[:PrefixLen]
	suffix := hash[PrefixLen:]

	body, err := c.fetchRange(prefix)
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

func (c *Client) fetchRange(prefix string) (string, error) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if len(prefix) != PrefixLen {
		return "", fmt.Errorf("hibp: prefix must be %d hex characters", PrefixLen)
	}

	if c.Cache != nil {
		if v, ok := c.Cache.Get(prefix); ok {
			return v, nil
		}
	}

	url := c.BaseURL + "/range/" + prefix
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return "", err
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
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hibp: API returned %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	s := string(body)
	if c.Cache != nil {
		c.Cache.Set(prefix, s, 5*time.Minute)
	}
	return s, nil
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
