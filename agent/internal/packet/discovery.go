package packet

import "encoding/binary"

// Discovery separates a TLS transport observation from evidence of HTTP or RDP.
// An HTTP ALPN offer is a candidate, not a server negotiation or web response.
func Discovery(b []byte) (scheme, host, source string, complete bool) {
	if len(b) > 0 && b[0] == 3 {
		if len(b) < 4 {
			return "", "", "", false
		}
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if b[1] != 0 || n < 19 || n > 4096 {
			return "", "", "", true
		}
		if len(b) < n {
			return "", "", "", false
		}
		// TPKT + X.224 connection request + the eight-byte RDP negotiation request.
		p := b[:n]
		x := p[n-8:]
		if int(p[4])+5 == n && p[5] == 0xe0 && p[10] == 0 && x[0] == 1 && binary.LittleEndian.Uint16(x[2:4]) == 8 && binary.LittleEndian.Uint32(x[4:]) <= 31 {
			return "https", "", "rdp_negotiation", true
		}
		return "", "", "", true
	}
	scheme, host, complete = Site(b)
	if scheme == "http" {
		return scheme, host, "http_host", complete
	}
	if scheme == "https" {
		if httpALPN(b) {
			return scheme, host, "tls_alpn", complete
		}
		return scheme, host, "tls_sni", complete
	}
	return scheme, host, "", complete
}

func httpALPN(b []byte) bool {
	if len(b) < 9 || b[0] != 22 || b[5] != 1 {
		return false
	}
	end := 5 + int(binary.BigEndian.Uint16(b[3:5]))
	if end > len(b) {
		return false
	}
	n := int(b[6])<<16 | int(b[7])<<8 | int(b[8])
	if n < 35 || 9+n > end {
		return false
	}
	b = b[9 : 9+n]
	i := 34 + 1 + int(b[34])
	if i+2 > len(b) {
		return false
	}
	i += 2 + int(binary.BigEndian.Uint16(b[i:i+2]))
	if i >= len(b) {
		return false
	}
	i += 1 + int(b[i])
	if i+2 > len(b) {
		return false
	}
	end = i + 2 + int(binary.BigEndian.Uint16(b[i:i+2]))
	i += 2
	if end != len(b) {
		return false
	}
	matched := false
	for i+4 <= end {
		t := binary.BigEndian.Uint16(b[i : i+2])
		n = int(binary.BigEndian.Uint16(b[i+2 : i+4]))
		i += 4
		if i+n > end {
			return false
		}
		if t == 16 {
			p := b[i : i+n]
			if len(p) < 3 || int(binary.BigEndian.Uint16(p[:2])) != len(p)-2 {
				return false
			}
			p = p[2:]
			for len(p) > 0 {
				sz := int(p[0])
				p = p[1:]
				if sz == 0 || sz > len(p) {
					return false
				}
				if string(p[:sz]) == "h2" || string(p[:sz]) == "http/1.1" {
					matched = true
				}
				p = p[sz:]
			}
		}
		i += n
	}
	return i == end && matched
}
