// Package entropy implements password entropy calculation.
//
// It estimates the entropy of a password in bits based on the character
// sets used and the password length, giving a measure of how unpredictable
// the password is.
//
// Entropy is calculated as:
//
//	bits = runeCount × log2(poolSize)
//
// where poolSize is the total number of possible characters based on
// which character sets (lowercase, uppercase, digits, symbols) are present.
package entropy

import (
	"math"
	"unicode"
)

// Character pool sizes for each set.
const (
	PoolLower  = 26
	PoolUpper  = 26
	PoolDigit  = 10
	PoolSymbol = 32
)

// CharsetInfo holds the results of a single-pass character set analysis.
type CharsetInfo struct {
	HasLower  bool // at least one lowercase letter
	HasUpper  bool // at least one uppercase letter
	HasDigit  bool // at least one digit
	HasSymbol bool // at least one symbol / punctuation
}

// SetCount returns how many of the four character set types are present.
func (c CharsetInfo) SetCount() int {
	n := 0
	if c.HasLower {
		n++
	}
	if c.HasUpper {
		n++
	}
	if c.HasDigit {
		n++
	}
	if c.HasSymbol {
		n++
	}
	return n
}

// PoolSize returns the total number of possible characters based on
// which sets are present.
func (c CharsetInfo) PoolSize() int {
	size := 0
	if c.HasLower {
		size += PoolLower
	}
	if c.HasUpper {
		size += PoolUpper
	}
	if c.HasDigit {
		size += PoolDigit
	}
	if c.HasSymbol {
		size += PoolSymbol
	}
	return size
}

// Calculate estimates the entropy of a password in bits.
//
// Length is measured in Unicode code points (runes), not bytes, so
// multi-byte characters are counted correctly.
func Calculate(password string) float64 {
	info, count := AnalyzeCharsets(password)
	if count == 0 {
		return 0
	}

	poolSize := info.PoolSize()
	if poolSize == 0 {
		return 0
	}

	return float64(count) * math.Log2(float64(poolSize))
}

// AnalyzeCharsets performs a single pass over the password to determine
// which character set types are present and counts the number of runes.
// Uses the unicode package for correct handling of non-ASCII letters and digits.
func AnalyzeCharsets(password string) (CharsetInfo, int) {
	var info CharsetInfo
	count := 0
	for _, r := range password {
		count++
		switch {
		case unicode.IsLower(r):
			info.HasLower = true
		case unicode.IsUpper(r):
			info.HasUpper = true
		case unicode.IsDigit(r):
			info.HasDigit = true
		case !unicode.IsSpace(r) && !unicode.IsControl(r):
			info.HasSymbol = true
		}
	}
	return info, count
}

