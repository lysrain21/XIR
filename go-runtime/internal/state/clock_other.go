//go:build !linux

package state

import (
	"os"
	"time"
)

var monotonicOrigin = time.Now()

// monotonicNanos is the portable fallback for hosts without CLOCK_MONOTONIC.
// The durable runner target is Linux; the fallback keeps the package buildable
// elsewhere without silently reporting wall-clock nanoseconds.
func monotonicNanos() (int64, error) {
	return int64(time.Since(monotonicOrigin)), nil
}

// threadID has no portable kernel thread id; the process id keeps the column
// populated on hosts without Linux's gettid(2).
func threadID() int { return os.Getpid() }
