package packet

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
)

// RequestMetadata retains the first request path and query names only, never
// credentials, cookies, query values or a request body. Long path segments are masked.
func RequestMetadata(b []byte) (method, path string, keys []string) {
	end := bytes.Index(b, []byte("\r\n"))
	if end < 0 {
		return
	}
	fields := strings.Fields(string(b[:end]))
	if len(fields) != 3 || !strings.HasPrefix(fields[2], "HTTP/1.") {
		return
	}
	u, err := url.ParseRequestURI(fields[1])
	if err != nil || u.IsAbs() || u.User != nil {
		return
	}
	method = fields[0]
	segments := strings.Split(u.EscapedPath(), "/")
	for i, segment := range segments {
		if len(segment) > 32 {
			segments[i] = ":redacted"
		}
	}
	path = strings.Join(segments, "/")
	if len(path) > 256 {
		path = path[:256]
	}
	for key := range u.Query() {
		if len(key) == 0 || len(key) > 32 {
			continue
		}
		valid := true
		for _, r := range key {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
				valid = false
				break
			}
		}
		if valid {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) > 8 {
		keys = keys[:8]
	}
	return
}

func Host(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) > 255 {
		return ""
	}
	if h, _, e := net.SplitHostPort(s); e == nil {
		s = h
	}
	s = strings.TrimSuffix(s, ".")
	s = strings.Trim(s, "[]")
	if a, e := netip.ParseAddr(s); e == nil {
		return a.Unmap().String()
	}
	if len(s) == 0 || len(s) > 253 {
		return ""
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return ""
			}
		}
	}
	return s
}

// Site reads only request headers / an unencrypted ClientHello. Empty host is
// a legitimate IP-only observation. No URLs, cookies or credentials are kept.
func Site(b []byte) (scheme, host string, complete bool) {
	for _, m := range []string{"GET ", "HEAD ", "POST ", "PUT ", "OPTIONS ", "DELETE ", "PATCH "} {
		if bytes.HasPrefix(b, []byte(m)) {
			end := bytes.Index(b, []byte("\r\n\r\n"))
			if end < 0 {
				return "", "", false
			}
			lines := strings.Split(string(b[:end]), "\r\n")
			if !strings.Contains(lines[0], " HTTP/1.") {
				return "", "", true
			}
			for _, l := range lines[1:] {
				if i := strings.IndexByte(l, ':'); i >= 0 && strings.EqualFold(l[:i], "host") {
					return "http", Host(l[i+1:]), true
				}
			}
			return "http", "", true
		}
	}
	if len(b) < 5 {
		return "", "", false
	}
	if b[0] != 22 || b[1] != 3 {
		return "", "", true
	}
	n := int(binary.BigEndian.Uint16(b[3:5]))
	if n > 16384 {
		return "", "", true
	}
	if len(b) < 5+n {
		return "", "", false
	}
	b = b[5 : 5+n]
	if len(b) < 4 || b[0] != 1 {
		return "", "", true
	}
	n = int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n > len(b)-4 {
		return "", "", true
	}
	b = b[4 : 4+n]
	if len(b) < 35 {
		return "", "", true
	}
	i := 34
	i += 1 + int(b[i])
	if i+2 > len(b) {
		return "", "", true
	}
	n = int(binary.BigEndian.Uint16(b[i : i+2]))
	i += 2 + n
	if i >= len(b) {
		return "", "", true
	}
	i += 1 + int(b[i])
	if i == len(b) {
		return "https", "", true
	}
	if i+2 > len(b) {
		return "", "", true
	}
	end := i + 2 + int(binary.BigEndian.Uint16(b[i:i+2]))
	i += 2
	if end > len(b) {
		return "", "", true
	}
	for i+4 <= end {
		t := binary.BigEndian.Uint16(b[i : i+2])
		l := int(binary.BigEndian.Uint16(b[i+2 : i+4]))
		i += 4
		if i+l > end {
			return "", "", true
		}
		if t == 0 && l >= 5 {
			s := b[i : i+l]
			total := int(binary.BigEndian.Uint16(s[:2]))
			if total != len(s)-2 {
				return "", "", true
			}
			s = s[2:]
			for len(s) >= 3 {
				kind := s[0]
				sz := int(binary.BigEndian.Uint16(s[1:3]))
				s = s[3:]
				if sz > len(s) {
					return "", "", true
				}
				if kind == 0 {
					return "https", Host(string(s[:sz])), true
				}
				s = s[sz:]
			}
		}
		i += l
	}
	return "https", "", true
}
