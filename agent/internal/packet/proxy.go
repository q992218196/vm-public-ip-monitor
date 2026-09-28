package packet

import (
	"encoding/binary"
	"math"
)

// ProxyTransport describes only the visible outer transport. It never names an
// encrypted proxy protocol, because ordinary applications can look identical.
func ProxyTransport(p Packet) string {
	b := p.Payload
	if p.Protocol == 6 {
		if len(b) >= 5 && b[0] == 22 && b[1] == 3 && b[2] <= 4 && int(b[3])<<8|int(b[4]) > 0 {
			return "tls"
		}
		if len(b) < 64 || knownPlaintext(b) || !highEntropy(b[:64]) {
			return ""
		}
		return "opaque_tcp"
	}
	if p.Protocol == 17 {
		if len(b) >= 1200 && b[0]&0xf0 == 0xc0 && binary.BigEndian.Uint32(b[1:5]) == 1 {
			return "quic"
		}
		if len(b) < 96 || p.DstPort == 53 || p.DstPort == 123 || !highEntropy(b[:64]) {
			return ""
		}
		return "opaque_udp"
	}
	return ""
}

func knownPlaintext(b []byte) bool {
	for _, prefix := range []string{"GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "PATCH ", "DELETE ", "CONNECT ", "SSH-", "RFB ", "PRI * HTTP/2.0", "EHLO ", "HELO "} {
		if len(b) >= len(prefix) && string(b[:len(prefix)]) == prefix {
			return true
		}
	}
	return false
}

func highEntropy(b []byte) bool {
	var counts [256]int
	for _, v := range b {
		counts[v]++
	}
	entropy := 0.0
	for _, count := range counts {
		if count > 0 {
			probability := float64(count) / float64(len(b))
			entropy -= probability * math.Log2(probability)
		}
	}
	return entropy >= 5.35
}
