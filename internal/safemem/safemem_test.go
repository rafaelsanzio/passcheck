package safemem

import (
	"testing"
)

func TestZero_ClearsData(t *testing.T) {
	b := []byte("s3cr3t-pa$$word!")
	Zero(b)

	if !IsZeroed(b) {
		t.Errorf("expected all zeros, got %v", b)
	}
}

func TestZero_EmptySlice(t *testing.T) {
	var b []byte
	Zero(b) // should not panic
	if !IsZeroed(b) {
		t.Error("empty slice should be considered zeroed")
	}
}

func TestZero_NilSlice(t *testing.T) {
	Zero(nil) // should not panic
}

func TestZero_SingleByte(t *testing.T) {
	b := []byte{0xFF}
	Zero(b)
	if b[0] != 0 {
		t.Errorf("expected 0, got %d", b[0])
	}
}

func TestZero_LargeSlice(t *testing.T) {
	b := make([]byte, 4096)
	for i := range b {
		b[i] = byte(i % 256)
	}
	Zero(b)
	if !IsZeroed(b) {
		t.Error("large slice should be fully zeroed")
	}
}

func TestIsZeroed_AllZeros(t *testing.T) {
	b := make([]byte, 16)
	if !IsZeroed(b) {
		t.Error("all-zero slice should return true")
	}
}

func TestIsZeroed_NonZero(t *testing.T) {
	b := []byte{0, 0, 1, 0}
	if IsZeroed(b) {
		t.Error("slice with non-zero byte should return false")
	}
}

func TestIsZeroed_Empty(t *testing.T) {
	if !IsZeroed([]byte{}) {
		t.Error("empty slice should be considered zeroed")
	}
}

func BenchmarkZero_16(b *testing.B) {
	buf := make([]byte, 16)
	for i := 0; i < b.N; i++ {
		Zero(buf)
	}
}

func BenchmarkZero_4096(b *testing.B) {
	buf := make([]byte, 4096)
	for i := 0; i < b.N; i++ {
		Zero(buf)
	}
}
