package packet

import (
	"encoding/binary"
	"net/netip"
)

type Packet struct {
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Seq              uint32
	AckSeq           uint32
	SYN, ACK, RST    bool
	Protocol         uint8
	Payload          []byte
	Size             int
}

// Decode only accepts complete Ethernet/IP headers. Fragmented transport and
// unsupported encapsulations are reported as skipped, never misinterpreted.
func Decode(b []byte, wireLen int) (p Packet, ok bool) {
	p.Size = wireLen
	if len(b) < 14 {
		return
	}
	et := binary.BigEndian.Uint16(b[12:14])
	off := 14
	for n := 0; et == 0x8100 || et == 0x88a8; n++ {
		if n >= 2 || len(b) < off+4 {
			return
		}
		et = binary.BigEndian.Uint16(b[off+2 : off+4])
		off += 4
	}
	if et == 0x0800 {
		if len(b) < off+20 || b[off]>>4 != 4 {
			return
		}
		h := int(b[off]&15) * 4
		total := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if h < 20 || total < h || len(b) < off+h || binary.BigEndian.Uint16(b[off+6:off+8])&0x3fff != 0 {
			return
		}
		p.Src = netip.AddrFrom4([4]byte(b[off+12 : off+16]))
		p.Dst = netip.AddrFrom4([4]byte(b[off+16 : off+20]))
		p.Protocol = b[off+9]
		if len(b) > off+total {
			b = b[:off+total]
		}
		off += h
	} else if et == 0x86dd {
		if len(b) < off+40 || b[off]>>4 != 6 {
			return
		}
		total := int(binary.BigEndian.Uint16(b[off+4 : off+6]))
		if total == 0 {
			return
		}
		p.Src = netip.AddrFrom16([16]byte(b[off+8 : off+24]))
		p.Dst = netip.AddrFrom16([16]byte(b[off+24 : off+40]))
		p.Protocol = b[off+6]
		if len(b) > off+40+total {
			b = b[:off+40+total]
		}
		off += 40
		for n := 0; p.Protocol == 0 || p.Protocol == 43 || p.Protocol == 60; n++ {
			if n >= 8 || len(b) < off+2 {
				return
			}
			h := (int(b[off+1]) + 1) * 8
			p.Protocol = b[off]
			off += h
			if off > len(b) {
				return
			}
		}
		if p.Protocol == 44 || p.Protocol == 50 || p.Protocol == 51 {
			return
		}
	} else {
		return
	}
	switch p.Protocol {
	case 6:
		if len(b) < off+20 {
			return
		}
		h := int(b[off+12]>>4) * 4
		if h < 20 || len(b) < off+h {
			return
		}
		p.SrcPort = binary.BigEndian.Uint16(b[off : off+2])
		p.DstPort = binary.BigEndian.Uint16(b[off+2 : off+4])
		p.Seq = binary.BigEndian.Uint32(b[off+4 : off+8])
		p.AckSeq = binary.BigEndian.Uint32(b[off+8 : off+12])
		p.SYN = b[off+13]&2 != 0
		p.ACK = b[off+13]&16 != 0
		p.RST = b[off+13]&4 != 0
		p.Payload = b[off+h:]
	case 17:
		if len(b) < off+8 {
			return
		}
		p.SrcPort = binary.BigEndian.Uint16(b[off : off+2])
		p.DstPort = binary.BigEndian.Uint16(b[off+2 : off+4])
		p.Payload = b[off+8:]
	}
	return p, true
}
