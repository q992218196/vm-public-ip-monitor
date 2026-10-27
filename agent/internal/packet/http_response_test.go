package packet

import (
	"strings"
	"testing"
)

func TestHTTPResponseStatusValidatesOnlyTheBoundedStatusLine(t *testing.T) {
	for _, test := range []struct {
		line     string
		status   int
		complete bool
	}{
		{"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nprivate-body", 200, true},
		{"HTTP/1.0 403 Forbidden\r\n", 403, true},
		{"HTTP/1.1 200 \r\n", 200, true},
		{"HTTP/1.1 200\r\n", 0, true},
		{"HTTP/1.1 100 Continue\r\n", 100, true},
		{"HTTP/1.1 599 Custom\r\n", 599, true},
		{"HTTP/1.1 20", 0, false},
		{"HTTP/1.1 200 OK\r", 0, false},
		{"SSH-2.0-OpenSSH_9.0\r\n", 0, true},
		{"GET / HTTP/1.1\r\n", 0, true},
		{"HTTP/2 200 OK\r\n", 0, true},
		{"HTTP/1.1 099 Invalid\r\n", 0, true},
		{"HTTP/1.1 600 Invalid\r\n", 0, true},
		{"HTTP/1.1 200OK\r\n", 0, true},
		{"HTTP/1.1 200 OK\n", 0, true},
		{"HTTP/1.1 200 O\x00K\r\n", 0, true},
		{"HTTP/1.1 200 " + strings.Repeat("x", 1024), 0, true},
	} {
		t.Run(test.line[:min(20, len(test.line))], func(t *testing.T) {
			status, complete := HTTPResponseStatus([]byte(test.line))
			if status != test.status || complete != test.complete {
				t.Fatalf("got %d/%v, expected %d/%v", status, complete, test.status, test.complete)
			}
		})
	}
}
