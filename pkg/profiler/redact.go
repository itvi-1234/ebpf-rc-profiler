//go:build linux

package profiler

import (
	"regexp"
	"strings"
)

const redacted = "[REDACTED]"

// sensitiveKeyParts marks environment variable names whose values are secrets.
// PWD is deliberately absent: it is the working directory, not a password.
var sensitiveKeyParts = []string{
	"PASSWORD", "PASSWD", "SECRET", "TOKEN", "CREDENTIAL",
	"PRIVATE_KEY", "API_KEY", "APIKEY", "ACCESS_KEY", "SIGNING_KEY",
	"AUTHORIZATION", "COOKIE",
}

// credentialURL matches the password in scheme://user:password@host.
var credentialURL = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:)[^@/\s]+@`)

// redactEnvValue hides secret values while keeping the variable name, which is
// what a Runtime Conditions profile needs.
func redactEnvValue(key, value string) string {
	upper := strings.ToUpper(key)
	for _, part := range sensitiveKeyParts {
		if strings.Contains(upper, part) {
			return redacted
		}
	}
	return credentialURL.ReplaceAllString(value, "${1}"+redacted+"@")
}

var sensitiveHeaders = map[string]bool{
	"authorization":        true,
	"proxy-authorization":  true,
	"cookie":               true,
	"set-cookie":           true,
	"x-api-key":            true,
	"x-auth-token":         true,
	"x-amz-security-token": true,
}

// redactHeaders returns a copy of headers with secret values hidden.
func redactHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	out := make(map[string]string, len(headers))
	for name, value := range headers {
		if sensitiveHeaders[strings.ToLower(name)] {
			out[name] = redacted
		} else {
			out[name] = value
		}
	}
	return out
}

var sensitiveHeaderLine = regexp.MustCompile(
	`(?im)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-amz-security-token):[^\r\n]*`)

// redactRawPayload hides secret header lines in a raw HTTP payload.
func redactRawPayload(payload string) string {
	return sensitiveHeaderLine.ReplaceAllString(payload, "${1}: "+redacted)
}
