// Package passphrase implements word-based entropy calculation for passphrases.
//
// For passphrases, entropy is calculated using the diceware model:
// entropy = wordCount × log2(dictSize)
//
// This gives a more accurate estimate for multi-word passphrases than
// character-based entropy, which underestimates their strength.
package passphrase

import "math"

// DefaultWordDictSize is the assumed dictionary size for word-based entropy
// calculation. Defaults to 7776 (diceware standard: 6^5 = 7776 words).
const DefaultWordDictSize = 7776

// CalculateWordEntropy computes entropy in bits for a passphrase using
// the diceware model: entropy = wordCount × log2(dictSize).
//
// wordCount is the number of distinct words in the passphrase.
// dictSize is the assumed dictionary size (default: 7776 for diceware).
//
// Returns 0 if wordCount is 0 or dictSize is <= 1.
func CalculateWordEntropy(wordCount int, dictSize int) float64 {
	if wordCount <= 0 || dictSize <= 1 {
		return 0
	}
	return float64(wordCount) * math.Log2(float64(dictSize))
}
