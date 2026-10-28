//go:build linux

package profiler

import (
	"crypto/tls"
	"net"
	"testing"
)

// realClientHello returns the first bytes a real Go TLS client sends.
func realClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		defer client.Close()
		_ = tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake()
	}()
	buf := make([]byte, 4096)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("reading client hello: %v", err)
	}
	return buf[:n]
}

func TestParseTLSClientHelloReadsServerName(t *testing.T) {
	hello := realClientHello(t, "api.frankfurter.dev")
	isTLS, name := parseTLSClientHello(hello)
	if !isTLS || name != "api.frankfurter.dev" {
		t.Fatalf("got isTLS=%v name=%q", isTLS, name)
	}
}

func TestParseTLSClientHelloTruncated(t *testing.T) {
	hello := realClientHello(t, "api.frankfurter.dev")
	for _, n := range []int{0, 3, 5, 6, 9, 20, 43, 50, 80} {
		if n > len(hello) {
			continue
		}
		// Must never panic, and must never invent a name.
		isTLS, name := parseTLSClientHello(hello[:n])
		if name != "" && name != "api.frankfurter.dev" {
			t.Fatalf("truncated at %d produced %q", n, name)
		}
		if n >= 6 && !isTLS {
			t.Fatalf("truncated at %d lost the TLS signal", n)
		}
	}
}

func TestParseTLSClientHelloRejectsNonTLS(t *testing.T) {
	cases := map[string][]byte{
		"http":     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		"postgres": {0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f},
		"redis":    []byte("*1\r\n$4\r\nPING\r\n"),
		"empty":    nil,
	}
	for name, payload := range cases {
		if isTLS, _ := parseTLSClientHello(payload); isTLS {
			t.Errorf("%s was detected as TLS", name)
		}
	}
}

func TestValidHostNameRejectsInjection(t *testing.T) {
	for _, bad := range []string{"", "a b", "evil\nname: x", "x\"y", "a/b"} {
		if validHostName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if !validHostName("db-1.internal_example.com") {
		t.Error("valid name rejected")
	}
}

func TestDetectConnectionIdentifiesHTTPSByServerName(t *testing.T) {
	hello := realClientHello(t, "api.frankfurter.dev")
	meta := ConnMeta{RemotePort: 443}

	got := DetectConnection(meta, hello)
	if !got.Matched || got.Protocol != ProtocolTLS || !got.TLS || got.ServerName != "api.frankfurter.dev" {
		t.Fatalf("unexpected result: %+v", got)
	}
	if got.Confidence < ConfidenceMedium {
		t.Fatalf("confidence %d is below the emit threshold", got.Confidence)
	}
}

func TestDetectConnectionTLSOnNonStandardPort(t *testing.T) {
	hello := realClientHello(t, "payments.internal")
	got := DetectConnection(ConnMeta{RemotePort: 8443}, hello)
	if got.Protocol != ProtocolTLS || got.ServerName != "payments.internal" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestDetectConnectionPlainProtocolsStillClassified(t *testing.T) {
	redis := DetectConnection(ConnMeta{RemotePort: 6379}, []byte("*1\r\n$4\r\nPING\r\n"))
	if redis.Protocol != ProtocolRedis || redis.TLS {
		t.Fatalf("redis regressed: %+v", redis)
	}
}

func TestIsTLSClientHelloOnlyForHellos(t *testing.T) {
	if !isTLSClientHello(realClientHello(t, "example.com")) {
		t.Error("real ClientHello not recognised")
	}
	// A ServerHello-style handshake record is TLS but not a ClientHello.
	if isTLSClientHello([]byte{0x16, 0x03, 0x03, 0x00, 0x30, 0x02, 0, 0, 0}) {
		t.Error("ServerHello treated as ClientHello")
	}
	if isTLSClientHello([]byte("GET / HTTP/1.1\r\n")) {
		t.Error("HTTP treated as TLS")
	}
}
