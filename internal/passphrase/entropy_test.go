package passphrase

import (
	"math"
	"testing"
)

func TestCalculateWordEntropy(t *testing.T) {
	tests := []struct {
		name      string
		wordCount int
		dictSize  int
		want      float64
	}{
		{"4 words, diceware", 4, 7776, 4 * math.Log2(7776)},
		{"5 words, diceware", 5, 7776, 5 * math.Log2(7776)},
		{"6 words, diceware", 6, 7776, 6 * math.Log2(7776)},
		{"4 words, small dict", 4, 1000, 4 * math.Log2(1000)},
		{"zero words", 0, 7776, 0},
		{"negative words", -1, 7776, 0},
		{"dict size 1", 4, 1, 0},
		{"dict size 0", 4, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateWordEntropy(tt.wordCount, tt.dictSize)
			if math.Abs(got-tt.want) > 0.001 {
				t.Errorf("CalculateWordEntropy(%d, %d) = %f, want %f", tt.wordCount, tt.dictSize, got, tt.want)
			}
		})
	}
}

func TestCalculateWordEntropy_Diceware(t *testing.T) {
	// Diceware standard: 4 words = ~51.6 bits, 5 words = ~64.5 bits
	entropy4 := CalculateWordEntropy(4, 7776)
	entropy5 := CalculateWordEntropy(5, 7776)

	if entropy4 < 50 || entropy4 > 52 {
		t.Errorf("4-word diceware entropy should be ~51.6 bits, got %f", entropy4)
	}
	if entropy5 < 64 || entropy5 > 65 {
		t.Errorf("5-word diceware entropy should be ~64.5 bits, got %f", entropy5)
	}
}
