//go:build linux

package profiler

// parseTLSClientHello reports whether b starts with a TLS handshake record and,
// when it is a ClientHello carrying a server_name extension, the requested host.
//
// The input is the first bytes seen on a connection, so it may be truncated.
// A truncated hello still reports isTLS = true, with an empty name when the
// extension was cut off.
func parseTLSClientHello(b []byte) (isTLS bool, serverName string) {
	// Record header: type(1) version(2) length(2). Handshake records are 0x16,
	// and TLS 1.0 to 1.3 all use a 0x03 major version on the wire.
	if len(b) < 6 || b[0] != 0x16 || b[1] != 0x03 || b[2] > 0x04 {
		return false, ""
	}
	// Handshake header: msg_type(1) length(3). Only ClientHello (0x01) carries SNI.
	if b[5] != 0x01 {
		return true, ""
	}

	p := 9      // record header (5) + handshake header (4)
	p += 2 + 32 // legacy_version + random
	if p >= len(b) {
		return true, ""
	}
	p += 1 + int(b[p]) // session id
	if p+2 > len(b) {
		return true, ""
	}
	p += 2 + int(be16(b[p:])) // cipher suites
	if p >= len(b) {
		return true, ""
	}
	p += 1 + int(b[p]) // compression methods
	if p+2 > len(b) {
		return true, ""
	}
	p += 2 // total extensions length; walk what we have

	for p+4 <= len(b) {
		extType := be16(b[p:])
		extLen := int(be16(b[p+2:]))
		p += 4
		if extType == 0x0000 { // server_name
			end := p + extLen
			if end > len(b) {
				return true, ""
			}
			return true, firstServerName(b[p:end])
		}
		p += extLen
	}
	return true, ""
}

// isTLSClientHello reports whether b is the start of a TLS ClientHello. It lets
// the profiler classify HTTPS on any port, not only the well-known ones.
func isTLSClientHello(b []byte) bool {
	isTLS, _ := parseTLSClientHello(b)
	return isTLS && len(b) > 5 && b[5] == 0x01
}

// firstServerName reads the host_name entry of a server_name extension body.
func firstServerName(ext []byte) string {
	// server_name_list length(2), then entries of name_type(1) length(2) name.
	if len(ext) < 5 || ext[2] != 0x00 {
		return ""
	}
	n := int(be16(ext[3:]))
	if 5+n > len(ext) {
		return ""
	}
	name := string(ext[5 : 5+n])
	if !validHostName(name) {
		return ""
	}
	return name
}

// validHostName keeps only plain DNS names so that attacker-controlled bytes
// never reach the YAML and JSON output.
func validHostName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

func be16(b []byte) uint16 {
	return uint16(b[0])<<8 | uint16(b[1])
}
