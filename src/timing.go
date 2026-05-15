package main

import (
	"crypto/rand"
	"math/big"
	"time"
)

// Timing hardening utilities to reduce detection via timing side-channels.
// Anti-tamper SDKs may measure app startup time and flag anomalies.

// jitteredSleep sleeps for the base duration plus a random jitter up to maxJitter.
// This prevents timing-based fingerprinting of the injection sequence.
func jitteredSleep(base time.Duration, maxJitter time.Duration) {
	jitter := time.Duration(0)
	if maxJitter > 0 {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(maxJitter)))
		if err == nil {
			jitter = time.Duration(n.Int64())
		}
	}
	time.Sleep(base + jitter)
}

// PollConfig holds timing parameters for polling loops.
type PollConfig struct {
	Interval     time.Duration // Base polling interval
	MaxJitter    time.Duration // Random jitter added to each poll
	Timeout      time.Duration // Total deadline
	FastStart    bool          // If true, first few polls are faster
	FastCount    int           // Number of fast polls before switching to normal
	FastInterval time.Duration // Interval for fast polls
}

// DefaultPollConfig returns timing parameters optimized for stealth.
// Tight polling with jitter to minimize the injection window while
// avoiding detectable periodic patterns.
func DefaultPollConfig() PollConfig {
	return PollConfig{
		Interval:     5 * time.Millisecond,
		MaxJitter:    3 * time.Millisecond,
		Timeout:      10 * time.Second,
		FastStart:    true,
		FastCount:    20,
		FastInterval: 1 * time.Millisecond,
	}
}

// ChildDetectionConfig returns timing for child process detection.
func ChildDetectionConfig() PollConfig {
	return PollConfig{
		Interval:     8 * time.Millisecond,
		MaxJitter:    4 * time.Millisecond,
		Timeout:      10 * time.Second,
		FastStart:    true,
		FastCount:    50,
		FastInterval: 2 * time.Millisecond,
	}
}

// PollWithConfig executes a polling function with the given timing config.
// Returns true if the check function returned true before timeout.
func PollWithConfig(cfg PollConfig, check func() bool) bool {
	deadline := time.Now().Add(cfg.Timeout)
	iteration := 0

	for time.Now().Before(deadline) {
		if check() {
			return true
		}

		iteration++
		if cfg.FastStart && iteration <= cfg.FastCount {
			jitteredSleep(cfg.FastInterval, cfg.MaxJitter/2)
		} else {
			jitteredSleep(cfg.Interval, cfg.MaxJitter)
		}
	}

	return false
}
