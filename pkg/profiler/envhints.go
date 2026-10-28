//go:build linux

package profiler

import (
	"sort"
	"strconv"
	"strings"
)

// parseEnviron parses the NUL-separated KEY=VALUE contents of /proc/<pid>/environ.
func parseEnviron(data []byte) map[string]string {
	env := make(map[string]string)
	for _, part := range strings.Split(string(data), "\x00") {
		if idx := strings.Index(part, "="); idx > 0 {
			env[part[:idx]] = part[idx+1:]
		}
	}
	return env
}

// envValueTokens splits a value such as "redis://cache:6379/0" into the pieces
// that can name a host or a port: "redis", "cache", "6379", "0".
func envValueTokens(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return false
		}
		return true
	})
}

// envNameHints returns the names of environment variables that hold the address
// of a connection: those with a value naming one of hosts, plus any variable
// holding exactly the port once a host variable was found (for DB_PORT style
// settings). Only names are returned, never values.
func envNameHints(env map[string]string, hosts []string, port uint16) []string {
	wanted := make(map[string]bool)
	for _, host := range hosts {
		if len(host) >= 3 {
			wanted[strings.ToLower(host)] = true
		}
	}
	if len(wanted) == 0 {
		return nil
	}

	matched := make(map[string]bool)
	for name, value := range env {
		for _, token := range envValueTokens(value) {
			if wanted[strings.ToLower(token)] {
				matched[name] = true
				break
			}
		}
	}
	if len(matched) == 0 {
		return nil
	}

	portText := strconv.Itoa(int(port))
	for name, value := range env {
		if strings.TrimSpace(value) == portText {
			matched[name] = true
		}
	}

	names := make([]string, 0, len(matched))
	for name := range matched {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
