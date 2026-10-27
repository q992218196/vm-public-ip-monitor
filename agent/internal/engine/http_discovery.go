package engine

import (
	"bytes"
	"strings"
	"time"

	"vm-monitor/agent/internal/packet"
	"vm-monitor/agent/internal/wire"
)

func (e *Engine) awaitHTTPResponse(st *stream, p packet.Packet, host string, now time.Time) {
	st.httpPending = true
	st.httpHost = strings.Clone(host)
	st.httpRequestEnd = st.next
	st.httpRequestAt = now
	st.next = p.AckSeq
	st.buf = nil
}

// Waiting requests share the existing stream count/TTL budget. The reverse
// connection must acknowledge the captured request and start at its expected
// server sequence; a different peer, stale tuple or stream gap is not proof.
func (e *Engine) observeHTTPResponse(p packet.Packet, now time.Time) bool {
	k := flowKey{p.Dst, p.Src, p.DstPort, p.SrcPort}
	st := e.streams[k]
	if st == nil || !st.httpPending {
		return false
	}
	if now.Before(st.httpRequestAt) || now.Sub(st.at) > 10*time.Second {
		delete(e.streams, k)
		e.health.ReassemblyDropped++
		return true
	}
	if len(p.Payload) == 0 {
		if p.FIN {
			delete(e.streams, k)
		}
		return true
	}
	if !p.ACK || int32(p.AckSeq-st.httpRequestEnd) < 0 {
		delete(e.streams, k)
		e.health.ReassemblyDropped++
		return true
	}
	if p.Seq != st.next {
		if int32(p.Seq-st.next) < 0 && int32(p.Seq+uint32(len(p.Payload))-st.next) <= 0 {
			return true
		}
		delete(e.streams, k)
		e.health.ReassemblyDropped++
		return true
	}
	const maxStatusLine = 1024
	n := len(p.Payload)
	if end := bytes.IndexByte(p.Payload, '\n'); end >= 0 {
		n = end + 1
	}
	if len(st.buf)+n > maxStatusLine {
		delete(e.streams, k)
		e.health.ReassemblyDropped++
		return true
	}
	st.buf = append(st.buf, p.Payload[:n]...)
	st.next += uint32(len(p.Payload))
	status, complete := packet.HTTPResponseStatus(st.buf)
	if !complete && !p.FIN {
		return true
	}
	delete(e.streams, k)
	if status != 0 {
		e.storeSite(wire.Site{IP: p.Src.String(), Port: p.SrcPort, Scheme: "http", Host: st.httpHost, Source: "http_response", HTTPStatus: status})
	}
	return true
}
