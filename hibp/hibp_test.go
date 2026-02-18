package hibp

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCheck_EmptyPassword(t *testing.T) {
	c := NewClient()
	breached, count, err := c.Check("")
	if err != nil {
		t.Fatalf("Check(\"\"): %v", err)
	}
	if breached || count != 0 {
		t.Errorf("empty password: breached=%v count=%d", breached, count)
	}
}

func TestCheckHash_InvalidHash(t *testing.T) {
	c := NewClient()
	_, _, err := c.CheckHash("short")
	if err == nil {
		t.Error("expected error for short hash")
	}
	_, _, err = c.CheckHash(strings.Repeat("x", 40))
	if err == nil {
		t.Error("expected error for non-hex hash")
	}
}

func TestCheckHash_ValidFormat_NotBreached(t *testing.T) {
	// Serve a range that does not contain our suffix.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/range/abc12" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		// Response: suffix:count per line. Our hash suffix will be 00000... (35 chars).
		w.Write([]byte("0000000000000000000000000000000000000:1\n"))
	}))
	defer server.Close()

	c := NewClient()
	c.BaseURL = server.URL
	c.HTTPClient = server.Client()
	// Hash prefix 5 chars + suffix 35 chars = 40 hex chars (SHA-1).
	hash := "abc12" + strings.Repeat("0", 35)
	breached, count, err := c.CheckHash(hash)
	if err != nil {
		t.Fatalf("CheckHash: %v", err)
	}
	if breached || count != 0 {
		t.Errorf("expected not breached: breached=%v count=%d", breached, count)
	}
}

func TestCheckHash_Breached(t *testing.T) {
	const suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
	const countVal = 10434004
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(suffix + ":" + strconv.Itoa(countVal) + "\n"))
	}))
	defer server.Close()

	c := NewClient()
	c.BaseURL = server.URL
	c.HTTPClient = server.Client()
	hash := "5BAA6" + strings.ToLower(suffix)
	breached, count, err := c.CheckHash(hash)
	if err != nil {
		t.Fatalf("CheckHash: %v", err)
	}
	if !breached {
		t.Error("expected breached")
	}
	if count != countVal {
		t.Errorf("count = %d, want %d", count, countVal)
	}
}

func TestCheck_PasswordSendsOnlyPrefix(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		// "password" SHA-1 first 5 chars = 5BAA6
		w.Write([]byte("something:1\n"))
	}))
	defer server.Close()

	c := NewClient()
	c.BaseURL = server.URL
	c.HTTPClient = server.Client()
	_, _, _ = c.Check("password")
	if path != "/range/5baa6" {
		t.Errorf("path = %s, want /range/5baa6 (only prefix sent)", path)
	}
}

func TestFetchRange_CacheHit(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte("SUFFIX:1\n"))
	}))
	defer server.Close()

	c := NewClient()
	c.BaseURL = server.URL
	c.HTTPClient = server.Client()
	c.Cache = NewMemoryCacheWithTTL(10, 5*time.Minute)

	hash := "abc12" + strings.Repeat("0", 35)
	_, _, _ = c.CheckHash(hash)
	_, _, _ = c.CheckHash(hash)
	if calls != 1 {
		t.Errorf("expected 1 API call (cache hit on second), got %d", calls)
	}
}

func TestMockClient(t *testing.T) {
	m := &MockClient{
		CheckFunc: func(password string) (bool, int, error) {
			if password == "breached" {
				return true, 42, nil
			}
			return false, 0, nil
		},
	}
	breached, count, err := m.Check("breached")
	if err != nil || !breached || count != 42 {
		t.Errorf("MockClient Check(breached): breached=%v count=%d err=%v", breached, count, err)
	}
	breached, count, _ = m.Check("safe")
	if breached || count != 0 {
		t.Errorf("MockClient Check(safe): breached=%v count=%d", breached, count)
	}
}

// --- Error handling (network failures, timeouts, non-200) ---

func TestCheckHash_APIReturnsNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewClient()
	c.BaseURL = server.URL
	c.HTTPClient = server.Client()
	hash := "abc12" + strings.Repeat("0", 35)
	_, _, err := c.CheckHash(hash)
	if err == nil {
		t.Error("expected error when API returns 500")
	}
}

func TestCheckHash_APIReturns429RateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	c := NewClient()
	c.BaseURL = server.URL
	c.HTTPClient = server.Client()
	hash := "abc12" + strings.Repeat("0", 35)
	_, _, err := c.CheckHash(hash)
	if err == nil {
		t.Error("expected error when API returns 429")
	}
}

func TestCheckHash_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Write([]byte("x:1\n"))
	}))
	defer server.Close()

	c := NewClient()
	c.BaseURL = server.URL
	c.HTTPClient = &http.Client{Timeout: 10 * time.Millisecond}
	hash := "abc12" + strings.Repeat("0", 35)
	_, _, err := c.CheckHash(hash)
	if err == nil {
		t.Error("expected error on timeout")
	}
}

func TestCheckHash_ConnectionFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("x:1\n")) }))
	baseURL := server.URL
	server.Close()
	// Now requests to baseURL will fail (connection refused or closed).
	c := NewClient()
	c.BaseURL = baseURL
	c.HTTPClient = &http.Client{Timeout: 100 * time.Millisecond}
	hash := "abc12" + strings.Repeat("0", 35)
	_, _, err := c.CheckHash(hash)
	if err == nil {
		t.Error("expected error when connection fails")
	}
}

// --- Benchmarks (performance AC: cached <100ms, API call <500ms) ---

func BenchmarkCheckHash_Cached(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("0000000000000000000000000000000000000:1\n"))
	}))
	defer server.Close()

	c := NewClient()
	c.BaseURL = server.URL
	c.HTTPClient = server.Client()
	c.Cache = NewMemoryCacheWithTTL(100, 5*time.Minute)
	hash := "abc12" + strings.Repeat("0", 35)
	// Prime the cache.
	_, _, _ = c.CheckHash(hash)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = c.CheckHash(hash)
	}
}

func BenchmarkCheckHash_Uncached(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("0000000000000000000000000000000000000:1\n"))
	}))
	defer server.Close()

	c := NewClient()
	c.BaseURL = server.URL
	c.HTTPClient = server.Client()
	hash := "abc12" + strings.Repeat("0", 35)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = c.CheckHash(hash)
	}
}

func BenchmarkCheck_Password(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("1e4c9b93f3f0682250b6cf8331b7ee68fd8:1\n"))
	}))
	defer server.Close()

	c := NewClient()
	c.BaseURL = server.URL
	c.HTTPClient = server.Client()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = c.Check("password")
	}
}
