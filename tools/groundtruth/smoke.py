# SPDX-License-Identifier: GPL-3.0-or-later
"""bring the lab up, touch every stand once, tear it down."""
import hashlib
import socket
import ssl
import sys
import time

import lab


def tcp(ip, port):
    t0 = time.monotonic()
    try:
        socket.create_connection((ip, port), 4).close()
        r = "open"
    except Exception as e:
        r = type(e).__name__
    return "%s %.0fms" % (r, (time.monotonic() - t0) * 1000)


def tls(ip, sni):
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    try:
        s = c.wrap_socket(socket.create_connection((ip, 443), 5), server_hostname=sni)
        d = s.getpeercert(True)
        v = s.version()
        s.close()
        return "%s cert=%s" % (v, hashlib.sha256(d).hexdigest()[:16])
    except Exception as e:
        return "fail %s" % e


def udp(ip, port, payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    s.connect((ip, port))
    s.send(payload)
    try:
        d = s.recv(4096)
        return "%d B %s" % (len(d), d[:4].hex())
    except Exception as e:
        return type(e).__name__
    finally:
        s.close()


def main():
    st, procs, notes = lab.start_all()
    try:
        time.sleep(1)
        for k, v in notes.items():
            print("note", k, v)
        for ip, port in [("127.0.1.1", 443), ("127.0.1.1", lab.HTTP_PORT), ("127.0.1.2", 4711), ("127.0.1.3", 443),
                         ("127.0.1.4", 443), ("127.0.1.5", 8388), ("127.0.1.11", 10808), ("127.0.1.9", 1050),
                         ("127.0.1.10", 443), ("127.0.1.15", 443), ("127.0.1.8", 443)]:
            print("tcp", ip, port, tcp(ip, port))
        for ip, sni in [("127.0.1.1", "lab-a.test"), ("127.0.1.3", "lab-a.test"),
                        ("127.0.1.4", "www.microsoft.com"), ("127.0.1.10", "lab-a.test")]:
            print("tls", ip, sni, tls(ip, sni))
        init = b"\x01\0\0\0" + bytes(range(144))
        print("udp W", udp("127.0.1.13", 51820, init))
        print("udp G", udp("127.0.1.16", 51820, bytes(8) + init))
        print("udp K", udp("127.0.1.14", 51820, init))
        print("udp F", udp("127.0.1.6", 51820, init))
        # quic-go drops an undecryptable Initial, so Q is checked by run.py only
        longhdr = b"\xc0\0\0\0\x01\x08" + bytes(8) + b"\x08" + bytes(range(8)) + bytes(1200)
        print("udp U", udp("127.0.1.18", 443, longhdr), udp("127.0.1.18", 8443, longhdr))
    finally:
        lab.stop_all(st, procs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
