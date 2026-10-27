package packet

import "bytes"

// HTTPResponseStatus reads a bounded HTTP/1.0 or HTTP/1.1 status line, never
// response headers or content. Complete also means an invalid prefix or line.
func HTTPResponseStatus(b []byte) (status int, complete bool) {
	const maxStatusLine = 1024
	validPrefix := false
	for _, prefix := range [][]byte{[]byte("HTTP/1.0 "), []byte("HTTP/1.1 ")} {
		if bytes.Equal(b[:min(len(b), len(prefix))], prefix[:min(len(b), len(prefix))]) {
			validPrefix = true
			break
		}
	}
	if !validPrefix {
		return 0, true
	}
	end := bytes.IndexByte(b, '\n')
	if end < 0 {
		return 0, len(b) >= maxStatusLine
	}
	if end == 0 || b[end-1] != '\r' || end+1 > maxStatusLine {
		return 0, true
	}
	line := b[:end-1]
	if len(line) < 13 || line[12] != ' ' {
		return 0, true
	}
	for _, c := range line[9:12] {
		if c < '0' || c > '9' {
			return 0, true
		}
		status = status*10 + int(c-'0')
	}
	if status < 100 || status > 599 {
		return 0, true
	}
	for _, c := range line[12:] {
		if c < 32 && c != '\t' || c == 127 {
			return 0, true
		}
	}
	return status, true
}
