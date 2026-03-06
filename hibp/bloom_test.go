package hibp

import (
	"bytes"
	"context"
	"testing"
)

func TestBloomFilter(t *testing.T) {
	// A rudimentary 64-bit Bloom filter with k=1.
	// Hashes:
	// "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8" (password)
	// sha1(hash): d3 48 ... -> h1 = 0xd348... % 64 = 23.
	// Let's just create an empty filter and see it's missing,
	// then fill it with all 1s and see it's present.
	
	ctx := context.Background()
	hash := "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8" // SHA-1 of "password"

	emptyArray := bytes.Repeat([]byte{0x00}, 8)
	bEmpty, _ := NewBloomFilter(bytes.NewReader(emptyArray), 64, 1)
	present, err := bEmpty.Has(ctx, hash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if present {
		t.Errorf("empty bloom filter should not contain hash %q", hash)
	}

	fullArray := bytes.Repeat([]byte{0xFF}, 8)
	bFull, _ := NewBloomFilter(bytes.NewReader(fullArray), 64, 1)
	presentFull, _ := bFull.Has(ctx, hash)
	if !presentFull {
		t.Errorf("full bloom filter should contain hash %q", hash)
	}
	
	invalidHash := "invalid"
	presentInv, _ := bFull.Has(ctx, invalidHash)
	if presentInv {
		t.Errorf("expected false for invalid hash length")
	}
}
