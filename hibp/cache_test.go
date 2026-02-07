package hibp

import (
	"sync"
	"testing"
	"time"
)

func TestMemoryCache_GetSet(t *testing.T) {
	c := NewMemoryCacheWithTTL(10, 5*time.Minute)
	if v, ok := c.Get("a"); ok || v != "" {
		t.Fatalf("empty cache Get: got %q, %v", v, ok)
	}
	c.Set("a", "va", time.Minute)
	v, ok := c.Get("a")
	if !ok || v != "va" {
		t.Errorf("Get after Set: got %q, %v", v, ok)
	}
}

func TestMemoryCache_Expiry(t *testing.T) {
	c := NewMemoryCacheWithTTL(10, 1*time.Millisecond)
	c.Set("k", "v", 1*time.Millisecond)
	time.Sleep(2 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Error("expected expired entry to be missing")
	}
}

func TestMemoryCache_Eviction(t *testing.T) {
	c := NewMemoryCache(2)
	c.Set("a", "1", time.Minute)
	c.Set("b", "2", time.Minute)
	c.Set("c", "3", time.Minute)
	if _, ok := c.Get("a"); ok {
		t.Error("expected first entry to be evicted")
	}
	if v, _ := c.Get("b"); v != "2" {
		t.Errorf("b = %q", v)
	}
	if v, _ := c.Get("c"); v != "3" {
		t.Errorf("c = %q", v)
	}
}

func TestMemoryCache_Concurrent(t *testing.T) {
	c := NewMemoryCacheWithTTL(100, time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(j int) {
			defer wg.Done()
			key := string(rune('a' + j))
			c.Set(key, key, time.Minute)
			c.Get(key)
		}(i)
	}
	wg.Wait()
}

// --- Benchmarks (performance AC) ---

func BenchmarkMemoryCache_GetHit(b *testing.B) {
	c := NewMemoryCacheWithTTL(100, time.Minute)
	c.Set("key", "value", time.Minute)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Get("key")
	}
}

func BenchmarkMemoryCache_Set(b *testing.B) {
	c := NewMemoryCacheWithTTL(10000, time.Minute)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set("key", "value", time.Minute)
	}
}

func BenchmarkMemoryCache_GetSetParallel(b *testing.B) {
	c := NewMemoryCacheWithTTL(10000, time.Minute)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		k := 0
		for pb.Next() {
			key := string(rune('a' + k%26))
			c.Set(key, "value", time.Minute)
			c.Get(key)
			k++
		}
	})
}
