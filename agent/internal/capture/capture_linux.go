//go:build linux

package capture

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// AF_PACKET capture is passive: no firewall, forwarding or OVS changes. Operators
// supply an interface that sees the public IP layer. SO_RCVBUF is bounded per fd.
func Run(ctx context.Context, iface string, bufferMiB int, consume func([]byte, int, string, time.Time), drops func(uint64)) error {
	ni, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(3)))
	if err != nil {
		return fmt.Errorf("AF_PACKET requires CAP_NET_RAW: %w", err)
	}
	defer syscall.Close(fd)
	if err = syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(3), Ifindex: ni.Index}); err != nil {
		return err
	}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, bufferMiB*1024*1024); err != nil {
		return err
	}
	if err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1}); err != nil {
		return err
	}
	// A mirror port must accept frames addressed to guests, without changing the
	// permanent interface flags. Membership is automatically released on close.
	mr := struct {
		Index     int32
		Type, Len uint16
		Addr      [8]byte
	}{Index: int32(ni.Index), Type: 1}
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), 263, 1, uintptr(unsafe.Pointer(&mr)), unsafe.Sizeof(mr), 0)
	if errno != 0 {
		return fmt.Errorf("PACKET_MR_PROMISC: %w", errno)
	}
	b := make([]byte, 65536)
	last := time.Now()
	for ctx.Err() == nil {
		n, _, e := syscall.Recvfrom(fd, b, syscall.MSG_TRUNC)
		if e != nil && e != syscall.EAGAIN && e != syscall.EWOULDBLOCK && e != syscall.EINTR {
			return e
		}
		if e == nil {
			size := n
			if n > len(b) {
				n = len(b)
			}
			consume(b[:n], size, iface, time.Now())
		}
		if time.Since(last) > 5*time.Second {
			var stats [2]uint32
			size := uint32(unsafe.Sizeof(stats))
			_, _, eno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), 263, 6, uintptr(unsafe.Pointer(&stats)), uintptr(unsafe.Pointer(&size)), 0)
			if eno == 0 {
				drops(uint64(stats[1]))
			}
			last = time.Now()
		}
	}
	return nil
}
func htons(n uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], n)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
func RSS() uint64 {
	b, e := os.ReadFile("/proc/self/statm")
	if e != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return 0
	}
	n, _ := strconv.ParseUint(f[1], 10, 64)
	return n * uint64(os.Getpagesize())
}

func StopSignals() []os.Signal { return []os.Signal{os.Interrupt, syscall.SIGTERM} }
