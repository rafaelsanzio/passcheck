package hibp

import (
	"sync"
	"time"
)

// DefaultCacheMaxEntries is the default maximum number of cached range responses.
const DefaultCacheMaxEntries = 1024

// DefaultCacheTTL is the default TTL for cached entries.
const DefaultCacheTTL = 5 * time.Minute

type cacheEntry struct {
	value  string
	expiry time.Time
}

// MemoryCache is an in-memory, thread-safe cache with TTL and optional max size.
// When maxEntries is 0, there is no size limit (only TTL eviction).
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	keys    []string
	max     int
	ttl     time.Duration
}

// NewMemoryCache returns a cache with the given max entries and default TTL.
// If maxEntries <= 0, size is unlimited.
func NewMemoryCache(maxEntries int) *MemoryCache {
	return &MemoryCache{
		entries: make(map[string]cacheEntry),
		keys:    make([]string, 0, 64),
		max:     maxEntries,
		ttl:     DefaultCacheTTL,
	}
}

// NewMemoryCacheWithTTL returns a cache with the given max entries and TTL.
func NewMemoryCacheWithTTL(maxEntries int, ttl time.Duration) *MemoryCache {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &MemoryCache{
		entries: make(map[string]cacheEntry),
		keys:    make([]string, 0, 64),
		max:     maxEntries,
		ttl:     ttl,
	}
}

// Get returns the cached value for key if present and not expired.
func (m *MemoryCache) Get(key string) (value string, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok || time.Now().After(e.expiry) {
		if ok {
			delete(m.entries, key)
			m.removeKey(key)
		}
		return "", false
	}
	return e.value, true
}

// Set stores value for key with the given TTL.
func (m *MemoryCache) Set(key, value string, ttl time.Duration) {
	if ttl <= 0 {
		ttl = m.ttl
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.entries[key]; !exists {
		if m.max > 0 && len(m.entries) >= m.max {
			m.evictOneLocked()
		}
		m.keys = append(m.keys, key)
	}
	m.entries[key] = cacheEntry{value: value, expiry: time.Now().Add(ttl)}
}

func (m *MemoryCache) evictOneLocked() {
	for len(m.keys) > 0 {
		k := m.keys[0]
		m.keys = m.keys[1:]
		if _, ok := m.entries[k]; ok {
			delete(m.entries, k)
			return
		}
	}
}

func (m *MemoryCache) removeKey(key string) {
	for i, k := range m.keys {
		if k == key {
			m.keys = append(m.keys[:i], m.keys[i+1:]...)
			return
		}
	}
}
