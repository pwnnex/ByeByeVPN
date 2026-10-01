# SPDX-License-Identifier: GPL-3.0-or-later
"""print the server hello extension order as it comes off the wire.

usage: python sh_order.py host[:port] [--tls12] [--ip ADDR]
one handshake per host, stops after ServerHello. re-observes ja4s_db seeds.
"""
import hashlib
import os
import socket
import struct
import sys


def ext(t, body):
    return struct.pack(">HH", t, len(body)) + body


def client_hello(host, tls12):
    exts = b""
    if host and not host.replace(".", "").isdigit():
        name = host.encode()
        exts += ext(0x0000, struct.pack(">HBH", len(name) + 3, 0, len(name)) + name)
    exts += ext(0x0017, b"")
    exts += ext(0xff01, b"\x00")
    exts += ext(0x000a, struct.pack(">HHHH", 6, 0x001d, 0x0017, 0x0018))
    exts += ext(0x000b, b"\x01\x00")
    exts += ext(0x0023, b"")
    alpn = b"\x02h2\x08http/1.1"
    exts += ext(0x0010, struct.pack(">H", len(alpn)) + alpn)
    sig = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    exts += ext(0x000d, struct.pack(">H", len(sig) * 2) + b"".join(struct.pack(">H", s) for s in sig))
    if not tls12:
        exts += ext(0x0033, struct.pack(">HHH", 36, 0x001d, 32) + os.urandom(32))
        exts += ext(0x002b, b"\x04\x03\x04\x03\x03")
    ciphers = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8]
    if tls12:
        ciphers = ciphers[3:]
    cs = b"".join(struct.pack(">H", c) for c in ciphers)
    body = b"\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32)
    body += struct.pack(">H", len(cs)) + cs + b"\x01\x00" + struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def read_exact(s, n):
    out = b""
    while len(out) < n:
        d = s.recv(n - len(out))
        if not d:
            raise EOFError("closed after %d bytes" % len(out))
        out += d
    return out


def server_hello_exts(addr, port, sni, tls12):
    s = socket.create_connection((addr, port), 8)
    s.settimeout(8)
    s.sendall(client_hello(sni, tls12))
    hdr = read_exact(s, 5)
    if hdr[0] != 0x16:
        raise ValueError("record type %02x (alert?) %s" % (hdr[0], read_exact(s, struct.unpack(">H", hdr[3:5])[0]).hex()))
    rec = read_exact(s, struct.unpack(">H", hdr[3:5])[0])
    s.close()
    if rec[0] != 2:
        raise ValueError("handshake type %d" % rec[0])
    p = 4 + 2 + 32
    sid = rec[p]; p += 1 + sid
    cipher = struct.unpack(">H", rec[p:p + 2])[0]; p += 2 + 1
    total = struct.unpack(">H", rec[p:p + 2])[0]; p += 2
    end = p + total
    order = []
    version = 0x0303
    while p < end:
        t, n = struct.unpack(">HH", rec[p:p + 4])
        if t == 0x002b:
            version = struct.unpack(">H", rec[p + 4:p + 6])[0]
        order.append(t)
        p += 4 + n
    return version, cipher, order


def main():
    target = sys.argv[1]
    tls12 = "--tls12" in sys.argv
    addr = None
    if "--ip" in sys.argv:
        addr = sys.argv[sys.argv.index("--ip") + 1]
    host, _, port = target.partition(":")
    port = int(port or 443)
    version, cipher, order = server_hello_exts(addr or host, port, host, tls12)
    wire = ",".join("%04x" % t for t in order)
    srt = ",".join("%04x" % t for t in sorted(order))
    h = lambda s: hashlib.sha256(s.encode()).hexdigest()[:12]
    print("%-22s v=%04x cipher=%04x exts=%d wire=[%s] ja4s_c=%s sorted_hash=%s" % (
        target, version, cipher, len(order), wire, h(wire), h(srt)))


if __name__ == "__main__":
    main()
