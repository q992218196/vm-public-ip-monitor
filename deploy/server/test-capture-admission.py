"""Exercise upload admission and FPM isolation in a disposable Compose stack."""

import concurrent.futures
import http.client
import socket
import select
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from queue import Queue
from urllib.parse import urlsplit


origin = urlsplit(sys.argv[1])
assert origin.scheme == "http", "Run against the local container HTTP entry"
host, port = origin.hostname, origin.port or 80
upload = "/api/v1/agent/captures/00000000-0000-4000-8000-000000000001/complete"


def status(path, method="GET", timeout=15):
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
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


# Occupy actual FPM workers via the private FastCGI listener. The temporary
# script is outside the web root: no public test route or application change.
compose = ["docker", "compose", "-f", "compose.yml", "-f", "compose.buildadmin.yml"]
app = subprocess.check_output(
    compose + ["ps", "-q", "app"], cwd=Path(__file__).resolve().parents[1], text=True
).strip()
assert app and "\n" not in app, "Expected one app container in the disposable test stack"
script = f"/var/www/html/storage/app/private/tmp/fpm-admission-{uuid.uuid4().hex}.php"
occupy = r'''
$path = $argv[1];
$connections = [];
$source = '<?php '
    . '$release = __FILE__.".release"; '
    . 'touch(__FILE__.".ready.".$_SERVER["HTTP_X_TEST_SLOT"]); '
    . '$deadline = microtime(true) + 40; '
    . 'do { usleep(100000); clearstatcache(true, $release); } '
    . 'while (!is_file($release) && microtime(true) < $deadline); '
    . 'echo "released";';
function fcgiRecord(int $type, string $content): string {
    return pack('CCnnCC', 1, $type, 1, strlen($content), 0, 0).$content;
}
function fcgiLength(int $length): string {
    return $length < 128 ? chr($length) : pack('N', $length | 0x80000000);
}
try {
    if (file_put_contents($path, $source) === false) {
        throw new RuntimeException('Cannot create private test script');
    }
    chmod($path, 0644);
    for ($slot = 0; $slot < 5; $slot++) {
        $connection = stream_socket_client('tcp://127.0.0.1:9000', $errno, $error, 5);
        if (!$connection) { throw new RuntimeException($error); }
        $connections[] = $connection;
        $params = '';
        foreach (['GATEWAY_INTERFACE' => 'CGI/1.1', 'REQUEST_METHOD' => 'GET',
            'SCRIPT_FILENAME' => $path, 'SCRIPT_NAME' => '/private-fpm-admission.php',
            'REQUEST_URI' => '/private-fpm-admission.php', 'SERVER_PROTOCOL' => 'HTTP/1.1',
            'HTTP_X_TEST_SLOT' => (string) $slot] as $name => $value) {
            $params .= fcgiLength(strlen($name)).fcgiLength(strlen($value)).$name.$value;
        }
        $request = fcgiRecord(1, pack('nCxxxxx', 1, 0)).fcgiRecord(4, $params)
            .fcgiRecord(4, '').fcgiRecord(5, '');
        while ($request !== '') {
            $written = fwrite($connection, $request);
            if (!$written) { throw new RuntimeException('FastCGI write failed'); }
            $request = substr($request, $written);
        }
    }
    $deadline = microtime(true) + 15;
    do {
        clearstatcache();
        $ready = count(glob($path.'.ready.*'));
        if ($ready === 5) { break; }
        usleep(100000);
    } while (microtime(true) < $deadline);
    if ($ready !== 5) { throw new RuntimeException("Only $ready www workers occupied"); }
    echo "Five www workers occupied\n";
    fflush(STDOUT);
    fgets(STDIN);
} finally {
    touch($path.'.release');
    foreach ($connections as $connection) {
        stream_set_timeout($connection, 3);
        while (!feof($connection) && fread($connection, 8192) !== '') {}
        fclose($connection);
    }
    foreach (glob($path.'.*') as $file) { unlink($file); }
    if (is_file($path)) { unlink($path); }
}
'''
process = subprocess.Popen(
    ["docker", "exec", "-i", app, "php", "-r", occupy, script],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
)
ready = Queue()
threading.Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True).start()
try:
    assert ready.get(timeout=20) == "Five www workers occupied\n", "Could not occupy the www pool"
    # Prove ordinary HTTP still uses the occupied pool, including a non-GET
    # request to a control URL; otherwise this would only test spare capacity.
    for path in ["/api/v1/agent/batches", "/api/v1/agent/update?version=1.6.0"]:
        try:
            result = status(path, "POST", timeout=0.4)
        except TimeoutError:
            pass
        else:
            raise AssertionError(f"Expected normal pool to be occupied, received {result} for {path}")
    started = time.monotonic()
    paths = ["/api/v1/agent/captures/claim", "/api/v1/agent/update?version=1.6.0"] * 18
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda path: status(path, timeout=3), paths))
    elapsed = time.monotonic() - started
    assert results == [401] * len(paths), f"Control requests lost authentication: {results}"
    assert elapsed < 6, f"Reserved control pool stalled for {elapsed:.1f}s"
finally:
    if process.poll() is None:
        try:
            process.stdin.write("release\n")
            process.stdin.flush()
        except BrokenPipeError:
            pass
    try:
        output, error = process.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        output, error = process.communicate()
        # The PHP client's finally block cannot run after SIGKILL. Release any
        # workers and remove only this test's uniquely named private files.
        subprocess.run(
            ["docker", "exec", app, "php", "-r",
             '$path=$argv[1];touch($path.".release");usleep(300000);'
             'foreach(glob($path.".*") as $file){unlink($file);}'
             'if(is_file($path)){unlink($path);}', script],
            check=True, timeout=10,
        )
        raise AssertionError(f"FPM test cleanup stalled: {error}")
    assert process.returncode == 0, f"FastCGI test failed: {output}\n{error}"

print("Five occupied www workers leave GET control requests authenticated and reachable through their reserved pool.")
