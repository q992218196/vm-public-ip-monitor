package packet

import (
	"encoding/binary"
	"testing"
)

func TestTLSClientHello(t *testing.T) {
	host := []byte("site.example")
	sni := []byte{0, byte(len(host) + 3), 0, 0, byte(len(host))}
	sni = append(sni, host...)
	ext := []byte{0, 0, 0, byte(len(sni))}
	ext = append(ext, sni...)
	body := make([]byte, 34)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0, 0, byte(len(ext)))
	body = append(body, ext...)
	hs := []byte{1, 0, 0, byte(len(body))}
	hs = append(hs, body...)
	r := []byte{22, 3, 1, 0, 0}
	binary.BigEndian.PutUint16(r[3:5], uint16(len(hs)))
	r = append(r, hs...)
	scheme, hostStr, ok := Site(r)
	if !ok || scheme != "https" || hostStr != "site.example" {
		t.Fatalf("%s %s %v", scheme, hostStr, ok)
	}
	for n := 0; n < len(r); n++ {
		Site(r[:n])
	}
}
func TestNormalizeHost(t *testing.T) {
	for input, want := range map[string]string{"Example.COM:8080": "example.com", "[2001:db8::1]:8443": "2001:db8::1", "evil.test/path": "", "user@host": "", "example.com.": "example.com"} {
		if got := Host(input); got != want {
			t.Fatalf("%q: %q", input, got)
		}
	}
}
func FuzzPacketNoPanic(f *testing.F) {
	f.Add([]byte{0, 1, 2})
	f.Fuzz(func(t *testing.T, b []byte) {
		Decode(b, len(b))
		if len(b) < 65536 {
			Site(b)
		}
	})
}
