package packet

import "testing"

func TestProxyTransportOnlyNamesOuterShape(t *testing.T) {
	random := make([]byte, 128)
	for i := range random {
		random[i] = byte(i)
	}
	if got := ProxyTransport(Packet{Protocol: 6, Payload: random}); got != "opaque_tcp" {
		t.Fatalf("opaque TCP: %q", got)
	}
	if got := ProxyTransport(Packet{Protocol: 6, Payload: []byte("GET / HTTP/1.1\r\nHost: example.org\r\n" + string(random))}); got != "" {
		t.Fatalf("HTTP must not be opaque: %q", got)
	}
	if got := ProxyTransport(Packet{Protocol: 6, Payload: []byte{22, 3, 3, 0, 32}}); got != "tls" {
		t.Fatalf("TLS: %q", got)
	}
	quic := make([]byte, 1200)
	quic[0], quic[4] = 0xc0, 1
	if got := ProxyTransport(Packet{Protocol: 17, Payload: quic}); got != "quic" {
		t.Fatalf("QUIC initial: %q", got)
	}
	if got := ProxyTransport(Packet{Protocol: 17, DstPort: 53, Payload: random}); got != "" {
		t.Fatalf("DNS port must not be opaque: %q", got)
	}
	if got := ProxyTransport(Packet{Protocol: 17, DstPort: 40000, Payload: random}); got != "opaque_udp" {
		t.Fatalf("opaque UDP: %q", got)
	}
}
