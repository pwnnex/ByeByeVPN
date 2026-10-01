# SPDX-License-Identifier: GPL-3.0-or-later
"""Local protocol regressions; no external service is contacted."""
import base64
import hashlib
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
        cert, key = Path(tmp) / 'cert.pem', Path(tmp) / 'key.pem'
        subprocess.run([exe, 'cert', str(cert), str(key), 'valid'], check=True, timeout=10)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        ctx.set_alpn_protocols(['h2', 'http/1.1'])

        def run(mode, response, encrypted=False, fragment=False):
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0))
            listener.listen(8)
            listener.settimeout(.1)
            port = listener.getsockname()[1]
            stop = threading.Event()
            errors, requests = [], []

            def serve():
                while not stop.is_set():
                    try:
                        client, _ = listener.accept()
                    except socket.timeout:
                        continue
                    try:
                        client.settimeout(2)
                        if encrypted:
                            client = ctx.wrap_socket(client, server_side=True)
                        with client:
                            data = b''
                            while True:
                                part = client.recv(4096)
                                if not part:
                                    break
                                data += part
                                if mode == 'grpc':
                                    if len(data) >= 42 and len(data) >= 42 + int.from_bytes(data[33:36], 'big'):
                                        break
                                elif b'\r\n\r\n' in data:
                                    break
                            requests.append(data)
                            if mode == 'ws':
                                assert f'Host: localhost:{port}\r\n'.encode() in data, data
                            payload = response(data) if callable(response) else response
                            if fragment:
                                for byte in payload:
                                    client.sendall(bytes([byte]))
                                    time.sleep(.001)
                            else:
                                client.sendall(payload)
                    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, ssl.SSLEOFError):
                        pass
                    except Exception as error:
                        errors.append(error)
                listener.close()

            worker = threading.Thread(target=serve)
            worker.start()
            try:
                result = subprocess.run([exe, mode, str(port)], capture_output=True, text=True,
                                        encoding='utf-8', timeout=12)
            finally:
                stop.set()
                worker.join(timeout=4)
            assert not worker.is_alive() and not errors, errors
            assert result.returncode == 0, result.stderr
            return json.loads(result.stdout), requests

        def ws_response(request):
            nonce = next(line.split(b':', 1)[1].strip() for line in request.split(b'\r\n') if line.lower().startswith(b'sec-websocket-key:'))
            assert len(base64.b64decode(nonce, validate=True)) == 16
            assert nonce != b'dGhlIHNhbXBsZSBub25jZQ=='
            accept = base64.b64encode(hashlib.sha1(nonce + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
            return b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n'

        report, requests = run('ws', ws_response, encrypted=True, fragment=True)
        assert report['tls_ports'][0]['websocket']['handshake_valid'], report
        assert report['score'] == 100 and report['tspu']['a_hits'] == report['tspu']['b_hits'] == 0
        assert len(requests) == 1
        report, requests = run('ws', b'HTTP/1.1 101 Switching Protocols\r\n\r\n', encrypted=True)
        assert not report['tls_ports'][0]['websocket']['handshake_valid'], report
        assert len(requests) == 6
        nonces = [next(x for x in req.split(b'\r\n') if x.startswith(b'Sec-WebSocket-Key:')) for req in requests]
        assert len(set(nonces)) == 6
        result, _ = run('plain', b'HTTP/1.1 302 Found\r\nLocation: https://warning.rt.ru/\r\n\r\n', fragment=True)
        assert result['service'] == 'HTTP' and result['redirect'] == 1, result
        result, _ = run('plain', b'HTTP/1.1 302 Found\r\nLocation: https://warning.rt.ru.evil.example/\r\n\r\n')
        assert result['redirect'] == 0, result
        result, _ = run('connect', b'HTTP/1.1 200 OK\r\n\r\n', fragment=True)
        assert result['connect_accepted'] == 1 and result['vpn_like'] == 0, result
        result, _ = run('connect', b'HTTP/1.1 200garbage\r\n\r\n')
        assert result['connect_accepted'] == 0, result
        result, _ = run('sstp', b'HTTP/1.1 500 SSTP error\r\n\r\nSSTP 18446744073709551615', encrypted=True)
        assert result['vpn_like'] == 0, result
        result, _ = run('sstp', b'HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n', encrypted=True, fragment=True)
        assert result['service'] == 'SSTP' and result['vpn_like'] == 1, result
        settings = b'\x00\x00\x00\x04\x00\x00\x00\x00\x00'
        reset = b'\x00\x00\x04\x03\x00\x00\x00\x00\x01\x00\x00\x00\x07'
        report, _ = run('grpc', settings + reset, encrypted=True, fragment=True)
        h2 = report['tls_ports'][0]['http2']
        assert h2['complete_frames_seen'] and not h2['grpc_confirmed'] and not h2['error'], report
        assert report['score'] == 100, report
        report, _ = run('grpc', settings + reset[:-1], encrypted=True)
        assert report['tls_ports'][0]['http2']['error'], report
        result = subprocess.run([exe, 'empty', '1'], capture_output=True, text=True, encoding='utf-8', check=True)
        report = json.loads(result.stdout)
        assert report['score'] is None and not report['score_available'] and report['label'] == 'INCONCLUSIVE', report
        assert not report['scan_coverage']['bgp_block_confirmed'] and report['tspu']['a_hits'] == 0
    print('protocol socket regressions passed (WebSocket, CONNECT, SSTP, redirects, HTTP/2, JSON)')


if __name__ == '__main__':
    main()
