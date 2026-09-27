package packet

import (
	"encoding/binary"
	"testing"
)

func TestVPNHandshakeSignatures(t *testing.T) {
	wgRequest := make([]byte, 148)
	wgRequest[0] = 1
	binary.LittleEndian.PutUint32(wgRequest[4:8], 123)
	wgResponse := make([]byte, 92)
	wgResponse[0] = 2
	binary.LittleEndian.PutUint32(wgResponse[4:8], 456)
	binary.LittleEndian.PutUint32(wgResponse[8:12], 123)
	ikeRequest := make([]byte, 32)
	binary.BigEndian.PutUint64(ikeRequest[:8], 123)
	ikeRequest[16], ikeRequest[17], ikeRequest[18], ikeRequest[19] = 33, 0x20, 34, 0x08
	binary.BigEndian.PutUint32(ikeRequest[24:28], uint32(len(ikeRequest)))
	ikeResponse := append([]byte(nil), ikeRequest...)
	binary.BigEndian.PutUint64(ikeResponse[8:16], 456)
	ikeResponse[19] = 0x28
	ovpnRequest := make([]byte, 14)
	ovpnRequest[0] = 7 << 3
	binary.BigEndian.PutUint64(ovpnRequest[1:9], 123)
	ovpnResponse := make([]byte, 26)
	ovpnResponse[0] = 8 << 3
	binary.BigEndian.PutUint64(ovpnResponse[1:9], 456)
	ovpnResponse[9] = 1
	binary.BigEndian.PutUint64(ovpnResponse[14:22], 123)

	for _, tc := range []struct {
		name, protocol, phase string
		port                  uint16
		payload               []byte
	}{
		{"wg-request", "wireguard", "request", 51820, wgRequest},
		{"wg-response", "wireguard", "response", 51820, wgResponse},
		{"ike-request", "ikev2", "request", 500, ikeRequest},
		{"ike-response", "ikev2", "response", 500, ikeResponse},
		{"openvpn-request", "openvpn", "request", 1194, ovpnRequest},
		{"openvpn-response", "openvpn", "response", 1194, ovpnResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, ok := VPN(Packet{Protocol: 17, SrcPort: tc.port, DstPort: tc.port, Payload: tc.payload})
			if !ok || s.Protocol != tc.protocol || s.Phase != tc.phase || len(s.HeaderHex) != 16 {
				t.Fatalf("unexpected signature %+v, %v", s, ok)
			}
		})
	}
	if _, ok := VPN(Packet{Protocol: 17, SrcPort: 51820, DstPort: 51820, Payload: make([]byte, 148)}); ok {
		t.Fatal("port and length alone must not identify WireGuard")
	}
	ikeRequest[17] = 0x30
	if _, ok := VPN(Packet{Protocol: 17, SrcPort: 500, DstPort: 500, Payload: ikeRequest}); ok {
		t.Fatal("wrong IKE version must not match")
	}
}
