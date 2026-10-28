//go:build linux

package profiler

import (
	"syscall"
	"testing"
)

func TestIPFromBytesUsesFamilyWhenKnown(t *testing.T) {
	v4 := ipFromBytes(syscall.AF_INET, []byte{10, 0, 0, 7})
	if v4.String() != "10.0.0.7" {
		t.Fatalf("got %v", v4)
	}
	v6 := make([]byte, 16)
	v6[0], v6[1], v6[15] = 0x26, 0x06, 0x01
	if got := ipFromBytes(syscall.AF_INET6, v6); got.String() != "2606::1" {
		t.Fatalf("got %v", got)
	}
}

func TestIPFromBytesInfersAddressWhenFamilyIsMissing(t *testing.T) {
	raw4 := make([]byte, 16)
	copy(raw4, []byte{192, 168, 1, 5})
	if got := ipFromBytes(0, raw4); got.String() != "192.168.1.5" {
		t.Fatalf("ipv4: got %v", got)
	}

	raw6 := make([]byte, 16)
	raw6[0], raw6[1], raw6[15] = 0x26, 0x06, 0x01
	if got := ipFromBytes(0, raw6); got.String() != "2606::1" {
		t.Fatalf("ipv6: got %v", got)
	}

	if got := ipFromBytes(0, make([]byte, 16)); got.IsValid() {
		t.Fatalf("all-zero address should stay invalid, got %v", got)
	}
}
