# SPDX-License-Identifier: GPL-3.0-or-later
"""Loopback TLS/HTTP regressions. The test driver creates temporary certificates."""
import gzip
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time


def main():
    exe = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory() as tmp:
        cert, key = Path(tmp) / "test.crt", Path(tmp) / "test.key"

        def context(expired=False):
            subprocess.run([exe, "cert", str(cert), str(key), "expired" if expired else "valid"], check=True, timeout=10)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            ctx.set_alpn_protocols(["http/1.1"])
            return ctx

        def run(mode, response=b"", ctx=None, fragments=False, delay=0):
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)
            port = listener.getsockname()[1]
            failures = []

            def serve():
                try:
                    client, _ = listener.accept()
                    client.settimeout(3)
                    if ctx is not None:
                        client = ctx.wrap_socket(client, server_side=True)
                    with client:
                        if mode == "tls":
                            client.recv(1)
                            return
                        request = b""
                        while b"\r\n\r\n" not in request:
                            chunk = client.recv(4096)
                            if not chunk: return
                            request += chunk
                        if mode == "http":
                            assert request.startswith(b"GET /lookup?q=test&output=json HTTP/1.1\r\n"), request
                        if delay: time.sleep(delay)
                        if fragments:
                            for byte in response:
                                client.sendall(bytes([byte]))
                                time.sleep(0.002)
                        else:
                            client.sendall(response)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, ssl.SSLEOFError):
                    pass
                except Exception as error:
                    failures.append(error)
                finally:
                    listener.close()

            worker = threading.Thread(target=serve)
            worker.start()
            start = time.monotonic()
            result = subprocess.run([exe, mode, str(port)], capture_output=True, text=True,
                                    encoding="utf-8", timeout=7)
            elapsed = time.monotonic() - start
            worker.join(timeout=6)
            assert not worker.is_alive() and not failures, failures
            assert result.returncode == 0, (result.returncode, result.stderr)
            return (json.loads(result.stdout) if mode != "http" else list(map(int, result.stdout.split()))), elapsed

        ctx = context()
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        report, _ = run("https", response, ctx, fragments=True)
        h = report["tls_ports"][0]["https"]
        assert h["request_sent"] and h["http_valid"] and h["headers_complete"], report
        assert h["server_header"] == "" and h["status_code"] == 200, report
        assert report["score_is_heuristic"] and not report["tspu"]["blocking_verified"]
        report, _ = run("https", b"HTTP/1.1 103 Early Hints\r\nServer: interim\r\n\r\n" + response, ctx)
        h = report["tls_ports"][0]["https"]
        assert h["http_valid"] and h["status_code"] == 200 and h["server_header"] == "", report
        for data in (b"HTTP/1.1 200 OK\r\nServer: partial", b"HTTP/1.1 200 OK\r\nX-Pad: " + b"a" * 18000):
            report, _ = run("https", data, ctx)
            h = report["tls_ports"][0]["https"]
            assert h["responded"] and not h["http_valid"] and h["error"], report
        report, elapsed = run("https", response, ctx, delay=1.5)
        assert elapsed < 1.4 and not report["tls_ports"][0]["https"]["http_valid"], (elapsed, report)
        report, _ = run("tls", ctx=ctx)
        tls = report["tls_ports"][0]
        assert tls["self_issued"] and tls["self_signed"] and tls["self_signature_checked"], report
        assert tls["certificate_times_valid"] and not tls["certificate_expired"], report
        assert not tls["certificate_trust_checked"], report
        report, _ = run("tls", ctx=context(expired=True))
        assert report["tls_ports"][0]["certificate_expired"], report
        for body, expected in [(b"[]", (1, 200, 2, 1, 0)), (b"<html>error</html>", (1, 200, 18, 0, 0))]:
            data = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
            result, _ = run("http", data)
            assert tuple(result) == expected, result
        partial = b"HTTP/1.1 200 OK\r\nContent-Length: 80\r\nConnection: close\r\n\r\n[]"
        result, _ = run("http", partial)
        assert result[0] == 0 and result[3:] == [0, 0], result
        compressed = gzip.compress(b"[]")
        data = (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: " +
                str(len(compressed)).encode() + b"\r\nConnection: close\r\n\r\n" + compressed)
        result, _ = run("http", data)
        # no accept-encoding on the wire, unsolicited gzip is an error
        assert result[0] == 0 and result[1] == 200 and result[3:] == [0, 0], result
        chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\n[]\r\n"
        result, _ = run("http", chunked + b"0\r\n\r\n")
        assert result == [1, 200, 2, 1, 0], result
        result, _ = run("http", chunked)
        assert result[0] == 0 and result[3:] == [0, 0], result
        large = b"HTTP/1.1 200 OK\r\nContent-Length: 530000\r\nConnection: close\r\n\r\n" + b" " * 530000
        result, _ = run("http", large)
        assert result[0] == 0 and result[2] <= 512 * 1024, result
    print("TLS/HTTP loopback regressions passed")


if __name__ == "__main__":
    main()
