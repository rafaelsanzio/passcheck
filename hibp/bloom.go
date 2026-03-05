package hibp

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"io"
)

// OfflineDB represents a local, offline database of breached passwords (e.g. a Bloom filter).
type OfflineDB interface {
	// Has checks if the lowercase 40-character SHA-1 hash is present in the database.
	// It should return true if the hash is definitely (or probably, for Bloom filters) breached.
	Has(ctx context.Context, hash string) (bool, error)
}

// BloomFilter is a probabilistic data structure for checking whether a
// password hash exists in an offline database.
type BloomFilter struct {
	bitset []byte
	m      uint64 // number of bits
	k      uint   // number of hash functions
}

// NewBloomFilter creates a Bloom filter from an io.Reader containing the raw bitset,
// along with the specified number of bits (m) and hash functions (k).
// The bitset size in bytes must be ceil(m / 8).
func NewBloomFilter(r io.Reader, m uint64, k uint) (*BloomFilter, error) {
	byteSize := (m + 7) / 8
	bitset := make([]byte, byteSize)
	if _, err := io.ReadFull(r, bitset); err != nil {
		return nil, err
	}
	return &BloomFilter{
		bitset: bitset,
		m:      m,
		k:      k,
	}, nil
}

// Has checks if the hash is likely present in the Bloom filter.
// hash must be a 40-character lowercase SHA-1 hex string.
func (f *BloomFilter) Has(ctx context.Context, hash string) (bool, error) {
	if len(hash) != SHA1HexLen {
		return false, nil
	}
	
	// Fast-path context check
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	h := sha1.Sum([]byte(hash))
	// We use the 160 bits (20 bytes) of SHA-1 to simulate k hash values.
	// We split as two 64-bit uints for double hashing.
	h1 := binary.BigEndian.Uint64(h[:8])
	h2 := binary.BigEndian.Uint64(h[8:16])

	for i := uint(0); i < f.k; i++ {
		// Double hashing: hash_i = h1 + i * h2
		idx := (h1 + uint64(i)*h2) % f.m
		byteIdx := idx / 8
		bitIdx := idx % 8
		if f.bitset[byteIdx]&(1<<bitIdx) == 0 {
			return false, nil // definitely not present
		}
	}
	return true, nil // probably present
}
