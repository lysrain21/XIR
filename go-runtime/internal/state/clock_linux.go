//go:build linux

package state

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// monotonicNanos returns CLOCK_MONOTONIC nanoseconds, the same clock Python's
// time.monotonic_ns() reports for the durable event ledger.
func monotonicNanos() (int64, error) {
	var stamp unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &stamp); err != nil {
		return 0, fmt.Errorf("xir state: CLOCK_MONOTONIC is unavailable: %w", err)
	}
	return stamp.Nano(), nil
}

// threadID returns the writing thread's kernel thread id, the Go equivalent of
// Python's threading.get_ident() evidence column.
func threadID() int { return unix.Gettid() }
