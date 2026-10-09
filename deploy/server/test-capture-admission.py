"""Exercise the real Nginx upload limit without consuming PHP worker slots."""

import concurrent.futures
import http.client
import socket
import select
import sys
import time
from urllib.parse import urlsplit


origin = urlsplit(sys.argv[1])
assert origin.scheme == "http", "Run against the local container HTTP entry"
host, port = origin.hostname, origin.port or 80
upload = "/api/v1/agent/captures/00000000-0000-4000-8000-000000000001/complete"


def status(path, method="GET"):
    connection = http.client.HTTPConnection(host, port, timeout=15)
    try:
        connection.request(method, path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


sockets = []
try:
    # Full headers with an incomplete body occupy Nginx upload slots; request
    # buffering keeps these requests out of PHP until the body is received.
    for _ in range(4):
        connection = socket.create_connection((host, port), timeout=15)
        sockets.append(connection)
        connection.sendall(
            f"POST {upload} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 24\r\n"
            "Content-Type: application/vnd.tcpdump.pcap\r\nConnection: close\r\n\r\nx".encode()
        )
        # Let the server process this header before opening the next connection.
        # Otherwise the fifth probe can win a slot and eject a parked upload.
        readable, _, _ = select.select([connection], [], [], 0.15)
        if readable:
            raise AssertionError(f"Parked upload was rejected: {connection.recv(1024)!r}")
    statuses = []
    for _ in range(20):
        statuses.append(status(upload, "POST"))
        if statuses[-1] == 429:
            break
        time.sleep(0.1)
    else:
        raise AssertionError(f"Expected a fifth upload to hit the four-upload limit; received {statuses}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _: status("/api/v1/agent/captures/claim"), range(36)))
    assert results == [401] * 36, f"Unauthenticated control polls must reach PHP: {results}"
    assert status("/api/v1/agent/update?version=1.5.0") == 401
    assert status("/api/v1/agent/batches", "POST") == 401
finally:
    for connection in sockets:
        connection.close()

print("Four occupied upload slots reject another upload with 429 while control polling and ingestion remain reachable.")
