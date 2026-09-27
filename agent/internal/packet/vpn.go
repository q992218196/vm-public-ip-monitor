package packet

import (
	"encoding/binary"
	"encoding/hex"
)

// VPNSignature recognizes only handshake structures visible in a single UDP
// datagram. A matching pair is required by the engine before reporting it.
type VPNSignature struct {
	Protocol  string
	Phase     string
	Session   uint64
	Length    int
	HeaderHex string
}

func VPN(p Packet) (VPNSignature, bool) {
	if p.Protocol != 17 || len(p.Payload) < 8 {
		return VPNSignature{}, false
	}
	b := p.Payload
	s := VPNSignature{Length: len(b), HeaderHex: hex.EncodeToString(b[:min(len(b), 8)])}
	if (len(b) == 148 || len(b) == 92) && b[1] == 0 && b[2] == 0 && b[3] == 0 {
		s.Protocol = "wireguard"
		if len(b) == 148 && b[0] == 1 {
			s.Phase = "request"
			s.Session = uint64(binary.LittleEndian.Uint32(b[4:8]))
		} else if len(b) == 92 && b[0] == 2 {
			s.Phase = "response"
			s.Session = uint64(binary.LittleEndian.Uint32(b[8:12]))
		}
		if s.Phase != "" && s.Session != 0 {
			return s, true
		}
	}
	// IKEv2 over UDP/4500 has a four-byte non-ESP marker.
	if p.SrcPort == 500 || p.DstPort == 500 || p.SrcPort == 4500 || p.DstPort == 4500 {
		h := b
		if p.SrcPort == 4500 || p.DstPort == 4500 {
			if len(h) < 4 || binary.BigEndian.Uint32(h[:4]) != 0 {
				return VPNSignature{}, false
			}
			h = h[4:]
		}
		if len(h) >= 32 && h[16] == 33 && h[17] == 0x20 && h[18] == 34 && binary.BigEndian.Uint32(h[20:24]) == 0 && int(binary.BigEndian.Uint32(h[24:28])) == len(h) {
			s.Protocol = "ikev2"
			s.Session = binary.BigEndian.Uint64(h[:8])
			if s.Session != 0 {
				if h[19]&0x20 == 0 && h[19]&0x08 != 0 && binary.BigEndian.Uint64(h[8:16]) == 0 {
					s.Phase = "request"
				} else if h[19]&0x20 != 0 && h[19]&0x08 != 0 && binary.BigEndian.Uint64(h[8:16]) != 0 {
					s.Phase = "response"
				}
				if s.Phase != "" {
					return s, true
				}
			}
		}
	}
	// Plain OpenVPN UDP hard-reset V2 control frames. tls-auth/tls-crypt
	// variants are intentionally excluded because their structure differs.
	if len(b) >= 14 && (b[0]>>3 == 7 || b[0]>>3 == 8) && binary.BigEndian.Uint64(b[1:9]) != 0 && b[9] <= 4 {
		ackCount := int(b[9])
		messageIDOffset := 10 + ackCount*4
		if ackCount > 0 {
			messageIDOffset += 8
		}
		if len(b) < messageIDOffset+4 || binary.BigEndian.Uint32(b[messageIDOffset:messageIDOffset+4]) != 0 {
			return VPNSignature{}, false
		}
		s.Protocol = "openvpn"
		if b[0]>>3 == 7 {
			s.Phase = "request"
		} else {
			s.Phase = "response"
		}
		return s, true
	}
	return VPNSignature{}, false
}
