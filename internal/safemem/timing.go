package safemem

import "time"

// SleepRemaining sleeps so that at least minDuration has passed since start.
// If minDuration is zero or negative, it returns immediately without sleeping.
// Use this to add execution-time padding when ConstantTimeMode is enabled,
// so that response time does not leak information about how much work was done.
//
// Call at the end of a sensitive operation:
//
//	start := time.Now()
//	// ... do work ...
//	SleepRemaining(start, cfg.MinExecutionTimeMs)
func SleepRemaining(start time.Time, minExecutionTimeMs int) {
	if minExecutionTimeMs <= 0 {
		return
	}
	minDur := time.Duration(minExecutionTimeMs) * time.Millisecond
	elapsed := time.Since(start)
	if elapsed < minDur {
		time.Sleep(minDur - elapsed)
	}
}
