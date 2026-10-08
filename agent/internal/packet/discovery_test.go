package packet

import (
	"encoding/binary"
	"testing"
)

func helloForDiscovery(protocols []string, sniFirst bool) []byte {
	ext := []byte{}
	add := func(kind uint16, data []byte) {
		h := []byte{byte(kind >> 8), byte(kind), byte(len(data) >> 8), byte(len(data))}
		ext = append(ext, h...)
		ext = append(ext, data...)
	}
	host := []byte("site.example")
	sni := append([]byte{0, byte(len(host) + 3), 0, 0, byte(len(host))}, host...)
	if sniFirst {
		add(0, sni)
	}
	list := []byte{}
	for _, p := range protocols {
		list = append(list, byte(len(p)))
		list = append(list, []byte(p)...)
	}
	if len(list) > 0 {
		add(16, append([]byte{0, byte(len(list))}, list...))
	}
	if !sniFirst {
		add(0, sni)
	}
	body := make([]byte, 34)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	record := append([]byte{22, 3, 1, 0, 0}, hs...)
	binary.BigEndian.PutUint16(record[3:5], uint16(len(hs)))
	return record
}

func TestDiscoveryALPNIsCandidateIndependentOfSNIOrder(t *testing.T) {
	for _, first := range []bool{false, true} {
		for _, protocols := range [][]string{{"h2", "http/1.1"}, {"http/1.1"}, {"mqtt"}, nil} {
			b := helloForDiscovery(protocols, first)
			scheme, host, source, complete := Discovery(b)
			want := "tls_sni"
			if len(protocols) > 0 && protocols[0] != "mqtt" {
				want = "tls_alpn"
			}
			if !complete || scheme != "https" || host != "site.example" || source != want {
				t.Fatalf("%v: %s %s %s", protocols, scheme, host, source)
			}
			for n := 0; n < len(b); n++ {
				_, _, _, complete = Discovery(b[:n])
				if complete && n >= 5 {
					t.Fatalf("truncated TLS accepted at %d", n)
				}
			}
		}
	}
}

func TestDiscoveryRDPRequiresStructuredNegotiationNotPort(t *testing.T) {
	b := []byte{3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0}
	scheme, host, source, complete := Discovery(b)
	if !complete || scheme != "https" || host != "" || source != "rdp_negotiation" {
		t.Fatal("RDP request not detected")
	}
	for n := 0; n < len(b); n++ {
		_, _, source, _ = Discovery(b[:n])
		if source != "" {
			t.Fatal("truncated RDP accepted")
		}
	}
	for _, pos := range []int{1, 4, 5, 10, 11, 13, 18} {
		bad := append([]byte{}, b...)
		bad[pos] ^= 0xff
		_, _, source, _ = Discovery(bad)
		if source == "rdp_negotiation" {
			t.Fatalf("invalid RDP at %d", pos)
		}
	}
	_, _, source, complete = Discovery([]byte("GET / HTTP/1.1\r\nHost: site.example\r\n\r\n"))
	if !complete || source != "http_host" {
		t.Fatal("HTTP not detected")
	}
}

func TestMalformedALPNNeverSuppliesHTTPProof(t *testing.T) {
	b := helloForDiscovery([]string{"h2"}, false)
	// ALPN is the first extension; corrupt its protocol-list size.
	b[56] = 255
	_, _, source, _ := Discovery(b)
	if source == "tls_alpn" {
		t.Fatal("malformed ALPN accepted")
	}
}
