//go:build linux

package profiler

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestKernelTimeIsWallClockTime(t *testing.T) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Skip(err)
	}
	now := uint64(ts.Sec)*uint64(time.Second) + uint64(ts.Nsec)

	got := kernelTime(now)
	if d := time.Since(got); d < -time.Second || d > time.Second {
		t.Fatalf("kernelTime is %v away from now (got %v)", d, got)
	}
	if got.Year() < 2024 {
		t.Fatalf("timestamp looks like an uptime, not a date: %v", got)
	}
}
