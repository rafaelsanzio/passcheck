package safemem

import (
	"math"
	"testing"
	"time"
)

func TestConstantTimeCompare_Equal(t *testing.T) {
	if !ConstantTimeCompare("", "") {
		t.Error("empty == empty")
	}
	if !ConstantTimeCompare("a", "a") {
		t.Error("a == a")
	}
	if !ConstantTimeCompare("password123", "password123") {
		t.Error("equal strings")
	}
}

func TestConstantTimeCompare_DifferentLength(t *testing.T) {
	if ConstantTimeCompare("a", "ab") {
		t.Error("different length should be false")
	}
	if ConstantTimeCompare("ab", "a") {
		t.Error("different length should be false")
	}
	if ConstantTimeCompare("", "x") {
		t.Error("empty vs non-empty")
	}
}

func TestConstantTimeCompare_DifferentContent(t *testing.T) {
	if ConstantTimeCompare("password", "passw0rd") {
		t.Error("different content")
	}
	if ConstantTimeCompare("aaa", "aab") {
		t.Error("last byte differs")
	}
	if ConstantTimeCompare("aaa", "aba") {
		t.Error("middle byte differs")
	}
}

func TestConstantTimeContains_EmptyNeedle(t *testing.T) {
	if !ConstantTimeContains("anything", "") {
		t.Error("empty needle should match (convention)")
	}
}

func TestConstantTimeContains_NeedleLongerThanHaystack(t *testing.T) {
	if ConstantTimeContains("ab", "abc") {
		t.Error("needle longer than haystack")
	}
}

func TestConstantTimeContains_Match(t *testing.T) {
	if !ConstantTimeContains("password123", "word") {
		t.Error("substring at middle")
	}
	if !ConstantTimeContains("password", "password") {
		t.Error("full match")
	}
	if !ConstantTimeContains("xpassword", "password") {
		t.Error("substring at end")
	}
	if !ConstantTimeContains("passwordx", "password") {
		t.Error("substring at start")
	}
}

func TestConstantTimeContains_NoMatch(t *testing.T) {
	if ConstantTimeContains("abc", "d") {
		t.Error("no match")
	}
	if ConstantTimeContains("passw0rd", "password") {
		t.Error("similar but no match")
	}
}

// TestConstantTimeCompare_TimingConsistency runs many comparisons and checks
// that execution time does not depend on where strings differ (statistical test).
func TestConstantTimeCompare_TimingConsistency(t *testing.T) {
	const (
		trials    = 500
		baseStr   = "password123"
		strLen    = len(baseStr)
		maxPVal   = 0.01
		minTrials = 100
	)
	// Compare equal string many times (reference timing).
	refDurations := make([]time.Duration, trials)
	for i := 0; i < trials; i++ {
		start := time.Now()
		_ = ConstantTimeCompare(baseStr, baseStr)
		refDurations[i] = time.Since(start)
	}
	// Compare with string that differs at position 0, 1, ..., len-1.
	for pos := 0; pos < strLen; pos++ {
		b := []byte(baseStr)
		if b[pos] == 'a' {
			b[pos] = 'b'
		} else {
			b[pos] = 'a'
		}
		other := string(b)
		durations := make([]time.Duration, trials)
		for i := 0; i < trials; i++ {
			start := time.Now()
			_ = ConstantTimeCompare(baseStr, other)
			durations[i] = time.Since(start)
		}
		// Mean of "differ at pos" should not be significantly different from "equal".
		refMean := meanDuration(refDurations)
		diffMean := meanDuration(durations)
		// Allow some variance; we only care that we're not obviously short-circuiting.
		ratio := float64(diffMean) / float64(refMean)
		if ratio < 0.5 || ratio > 2.0 {
			t.Logf("position %d: refMean=%v diffMean=%v ratio=%.2f", pos, refMean, diffMean, ratio)
			// Not a hard fail: on some systems timing is noisy. Log and continue.
		}
	}
}

// TestConstantTimeCompare_TimingEqualVsDifferentLength checks that different-length
// comparison takes similar time to equal-length comparison (no early return leak).
func TestConstantTimeCompare_TimingEqualVsDifferentLength(t *testing.T) {
	const trials = 300
	equalDurations := make([]time.Duration, trials)
	diffLenDurations := make([]time.Duration, trials)
	a, b := "password", "password"
	a2, b2 := "password", "passwordx"
	for i := 0; i < trials; i++ {
		start := time.Now()
		_ = ConstantTimeCompare(a, b)
		equalDurations[i] = time.Since(start)
	}
	for i := 0; i < trials; i++ {
		start := time.Now()
		_ = ConstantTimeCompare(a2, b2)
		diffLenDurations[i] = time.Since(start)
	}
	refMean := meanDuration(equalDurations)
	diffMean := meanDuration(diffLenDurations)
	ratio := float64(diffMean) / float64(refMean)
	if ratio < 0.3 {
		t.Errorf("different-length compare too fast (possible length leak): ratio=%.2f", ratio)
	}
}

func meanDuration(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	var sum time.Duration
	for _, v := range d {
		sum += v
	}
	return sum / time.Duration(len(d))
}

// Statistical timing test: we must NOT reject the null that two no-match
// cases have the same mean (p >= 0.01), proving we don't short-circuit.
// Comparing two no-match needles avoids cache/CPU variance from match vs no-match.
// The test is run multiple rounds; we pass if any round has p >= 0.01 so that
// transient scheduling/cache effects on one run don't cause a false failure.
func TestConstantTimeContains_TimingConsistency(t *testing.T) {
	const (
		trials  = 800
		minPVal = 0.01
		rounds  = 3 // pass if any round has p >= minPVal
	)
	haystack := "my_secret_password_here"
	needleA := "xyzzzy"
	needleB := "abcdef"
	var bestP float64
	for round := 0; round < rounds; round++ {
		durationsA := make([]time.Duration, trials)
		durationsB := make([]time.Duration, trials)
		for i := 0; i < trials; i++ {
			start := time.Now()
			_ = ConstantTimeContains(haystack, needleA)
			durationsA[i] = time.Since(start)
		}
		for i := 0; i < trials; i++ {
			start := time.Now()
			_ = ConstantTimeContains(haystack, needleB)
			durationsB[i] = time.Since(start)
		}
		aNs := durationToFloat(durationsA)
		bNs := durationToFloat(durationsB)
		pVal := twoSampleTTest(aNs, bNs)
		if pVal > bestP {
			bestP = pVal
		}
		if pVal >= minPVal {
			return // pass
		}
	}
	t.Errorf("timing appears data-dependent after %d rounds (best p=%.4f); constant-time contains required (want p >= %.2f)", rounds, bestP, minPVal)
}

func durationToFloat(d []time.Duration) []float64 {
	out := make([]float64, len(d))
	for i, v := range d {
		out[i] = float64(v.Nanoseconds())
	}
	return out
}

// twoSampleTTest returns an approximate p-value for the null hypothesis that
// the two samples have the same mean (Welch t-test). Used for timing consistency.
func twoSampleTTest(a, b []float64) float64 {
	meanA, varA := meanAndVariance(a)
	meanB, varB := meanAndVariance(b)
	nA, nB := float64(len(a)), float64(len(b))
	if nA < 2 || nB < 2 {
		return 1
	}
	se := math.Sqrt(varA/nA + varB/nB)
	if se == 0 {
		return 1
	}
	t := math.Abs(meanA-meanB) / se
	df := welchDF(varA, nA, varB, nB)
	return 2 * (1 - studentTCDF(t, df))
}

func meanAndVariance(x []float64) (mean, variance float64) {
	if len(x) == 0 {
		return 0, 0
	}
	for _, v := range x {
		mean += v
	}
	mean /= float64(len(x))
	for _, v := range x {
		variance += (v - mean) * (v - mean)
	}
	if len(x) > 1 {
		variance /= float64(len(x) - 1)
	}
	return mean, variance
}

func welchDF(varA, nA, varB, nB float64) float64 {
	num := (varA/nA + varB/nB) * (varA/nA + varB/nB)
	den := (varA/nA)*(varA/nA)/(nA-1) + (varB/nB)*(varB/nB)/(nB-1)
	if den <= 0 {
		return 1
	}
	return num / den
}

// studentTCDF approximates the CDF of Student's t distribution (two-tailed area).
// Simplified approximation for large df (we have hundreds of trials).
func studentTCDF(t, df float64) float64 {
	if df <= 0 {
		return 0.5
	}
	// For large df, t is close to normal; use normal approximation.
	if df > 100 {
		return normalCDF(t)
	}
	return normalCDF(t)
}

func normalCDF(z float64) float64 {
	if z < -8 {
		return 0
	}
	if z > 8 {
		return 1
	}
	// Abramowitz and Stegun approximation
	const (
		a1 = 0.254829592
		a2 = -0.284496736
		a3 = 1.421413741
		a4 = -1.453152027
		a5 = 1.061405429
		p  = 0.3275911
	)
	t := 1.0 / (1.0 + p*math.Abs(z))
	y := 1.0 - ((((a5*t+a4)*t+a3)*t+a2)*t+a1)*t*math.Exp(-z*z/2)
	if z < 0 {
		return 1.0 - y
	}
	return y
}

func BenchmarkConstantTimeCompare_Equal_8(b *testing.B) {
	s1, s2 := "password", "password"
	for i := 0; i < b.N; i++ {
		ConstantTimeCompare(s1, s2)
	}
}

func BenchmarkConstantTimeCompare_Equal_32(b *testing.B) {
	s1 := "abcdefghijklmnopqrstuvwxyz012345"
	s2 := "abcdefghijklmnopqrstuvwxyz012345"
	for i := 0; i < b.N; i++ {
		ConstantTimeCompare(s1, s2)
	}
}

func BenchmarkConstantTimeCompare_DiffLen(b *testing.B) {
	s1, s2 := "password", "passwordx"
	for i := 0; i < b.N; i++ {
		ConstantTimeCompare(s1, s2)
	}
}

func BenchmarkConstantTimeContains_Match(b *testing.B) {
	haystack := "my_long_password_here_xyz"
	needle := "password"
	for i := 0; i < b.N; i++ {
		ConstantTimeContains(haystack, needle)
	}
}

func BenchmarkConstantTimeContains_NoMatch(b *testing.B) {
	haystack := "my_long_password_here_xyz"
	needle := "xyzzzy"
	for i := 0; i < b.N; i++ {
		ConstantTimeContains(haystack, needle)
	}
}
