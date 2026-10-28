//go:build linux

package profiler

import (
	"time"

	"golang.org/x/sys/unix"
)

// monotonicToWall is the offset between the kernel monotonic clock and the wall
// clock, measured once at startup. bpf_ktime_get_ns() reports CLOCK_MONOTONIC
// (time since boot), not time since the Unix epoch.
var monotonicToWall = measureClockOffset()

func measureClockOffset() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return time.Now().UnixNano() - (ts.Sec*int64(time.Second) + ts.Nsec)
}

// kernelTime converts a bpf_ktime_get_ns() value into wall-clock time.
func kernelTime(ns uint64) time.Time {
	return time.Unix(0, int64(ns)+monotonicToWall)
}
