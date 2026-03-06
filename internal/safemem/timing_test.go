package safemem

import (
	"testing"
	"time"
)

func TestSleepRemaining_NonPositiveDuration(t *testing.T) {
	start := time.Now()

	SleepRemaining(start, 0)
	SleepRemaining(start, -10)
}

func TestSleepRemaining_SmallPositiveDuration(t *testing.T) {
	// Use a very small minimum duration to avoid flaky timing on CI while
	// still exercising the sleep path.
	start := time.Now()
	SleepRemaining(start, 1)
}

