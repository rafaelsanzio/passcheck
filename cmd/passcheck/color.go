package main

import "fmt"

// ANSI escape codes for terminal colors.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiGreen  = "\033[32m"
)

// Score thresholds for color mapping (mirrors internal/scoring thresholds).
const (
	colorThresholdVeryWeak = 20
	colorThresholdWeak     = 40
	colorThresholdOkay     = 60
	colorThresholdStrong   = 80
)

// Score meter constants.
const (
	meterSegments = 10
	maxScore      = 100
)

// colorize wraps s with an ANSI color code and a reset suffix.
func colorize(s, code string) string {
	return fmt.Sprintf("%s%s%s", code, s, ansiReset)
}

// verdictColor returns the ANSI color code for a verdict string.
func verdictColor(verdict string) string {
	switch verdict {
	case "Very Weak":
		return ansiRed + ansiBold
	case "Weak":
		return ansiRed
	case "Okay":
		return ansiYellow
	case "Strong":
		return ansiGreen
	case "Very Strong":
		return ansiGreen + ansiBold
	default:
		return ""
	}
}

// scoreColor returns the ANSI color code for a numeric score.
func scoreColor(score int) string {
	switch {
	case score <= colorThresholdVeryWeak:
		return ansiRed + ansiBold
	case score <= colorThresholdWeak:
		return ansiRed
	case score <= colorThresholdOkay:
		return ansiYellow
	case score <= colorThresholdStrong:
		return ansiGreen
	default:
		return ansiGreen + ansiBold
	}
}

// scoreMeter builds a visual score bar with meterSegments segments.
//
//	[████████░░] 80/100
func scoreMeter(score int, useColor bool) string {
	filled := score / meterSegments
	if filled > meterSegments {
		filled = meterSegments
	}
	empty := meterSegments - filled

	var bar string
	for i := 0; i < filled; i++ {
		bar += "█"
	}
	for i := 0; i < empty; i++ {
		bar += "░"
	}

	meter := fmt.Sprintf("[%s] %d/%d", bar, score, maxScore)
	if useColor {
		meter = colorize(fmt.Sprintf("[%s]", bar), scoreColor(score)) +
			fmt.Sprintf(" %d/%d", score, maxScore)
	}
	return meter
}
