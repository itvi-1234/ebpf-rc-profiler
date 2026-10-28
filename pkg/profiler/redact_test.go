//go:build linux

package profiler

import "testing"

func TestRedactEnvValue(t *testing.T) {
	cases := []struct{ key, value, want string }{
		{"DB_PASSWORD", "hunter2", redacted},
		{"API_TOKEN", "abc", redacted},
		{"AWS_SECRET_ACCESS_KEY", "abc", redacted},
		{"DB_HOST", "postgres.default.svc", "postgres.default.svc"},
		{"PWD", "/home/app", "/home/app"},
		{"PATH", "/usr/bin", "/usr/bin"},
		{"DATABASE_URL", "postgres://app:hunter2@db:5432/app", "postgres://app:" + redacted + "@db:5432/app"},
		{"REDIS_URL", "redis://cache:6379", "redis://cache:6379"},
	}
	for _, c := range cases {
		if got := redactEnvValue(c.key, c.value); got != c.want {
			t.Errorf("%s: got %q, want %q", c.key, got, c.want)
		}
	}
}

func TestRedactHeadersKeepsOriginal(t *testing.T) {
	in := map[string]string{"Authorization": "Bearer x", "Host": "example.com", "cookie": "s=1"}
	out := redactHeaders(in)
	if out["Authorization"] != redacted || out["cookie"] != redacted || out["Host"] != "example.com" {
		t.Fatalf("unexpected: %v", out)
	}
	if in["Authorization"] != "Bearer x" {
		t.Fatal("input was modified")
	}
}

func TestRedactRawPayload(t *testing.T) {
	in := "POST /charge HTTP/1.1\r\nHost: pay\r\nAuthorization: Bearer secret\r\nX-Api-Key: k\r\n\r\n{}"
	got := redactRawPayload(in)
	want := "POST /charge HTTP/1.1\r\nHost: pay\r\nAuthorization: " + redacted + "\r\nX-Api-Key: " + redacted + "\r\n\r\n{}"
	if got != want {
		t.Fatalf("got %q", got)
	}
}
