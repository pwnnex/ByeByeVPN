# SPDX-License-Identifier: GPL-3.0-or-later
"""client captures for `byebyevpn pcap`, recorded on loopback.

a real xray client talks to a real xray server through a relay that writes
every chunk it forwards, with its time, into a pcap. the inner client is
python's openssl doing tls to a lab web origin through the tunnel, the way
a browser does through a proxy. the plain case is the same client going to
the origin with no tunnel at all.

usage: python capture_lab.py [outdir]   (writes <case>.pcap, prints the paths)
"""
import hashlib
import json
import os
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import uuid

import lab

TARGET = "127.0.2.1"        # lab web origin, tls on 443
NODE = "127.0.2.2"          # xray server inbounds
RELAY = "127.0.2.3"         # recording relays in front of the node and the origin
CLIENT = "127.0.2.4"        # xray client, one dokodemo inbound per case

# addresses written into the pcaps
PCAP_CLIENT = bytes([192, 0, 2, 10])
PCAP_NODE = bytes([203, 0, 113, 5])
PCAP_NODE_TEXT = "203.0.113.5"

# case: node port (or the origin for plain), dokodemo port, what it is
CASES = {
    "vless-tls": dict(port=8443, local=1081, what="VLESS over TLS, no flow"),
    "vless-vision": dict(port=8444, local=1082, what="VLESS over TLS, flow xtls-rprx-vision"),
    "trojan-tls": dict(port=8445, local=1083, what="Trojan over TLS"),
    "plain-https": dict(port=9443, local=None, what="the same client straight to the origin, keep-alive"),
}
CONNECTIONS = 4
PAGE = secrets.token_bytes(6000).hex().encode()   # 12 KB body
COOKIE = secrets.token_hex(150).encode()

# wall clock ticks can be coarse on windows; flights need fine order
_WALL, _PERF = time.time_ns(), time.perf_counter_ns()


def now_ns():
    return _WALL + time.perf_counter_ns() - _PERF


# ---------------------------------------------------------------- origin

def origin_handler_factory(ctx):
    def handler(conn):
        conn.settimeout(5)
        try:
            t = ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            return
        while True:
            head = lab.read_head(t)
            if not head:
                return
            keep = b"connection: close" not in head.lower()
            t.sendall(b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/plain\r\nContent-Length: " +
                      str(len(PAGE)).encode() + (b"\r\n\r\n" if keep else b"\r\nConnection: close\r\n\r\n") + PAGE)
            if not keep:
                return
    return handler


# ---------------------------------------------------------------- recording relay

class Recorder:
    def __init__(self):
        self.lock = threading.Lock()
        self.conns = []          # [(events)], events: (ns, up, bytes) or (ns, "fin", up)

    def relay_factory(self, dst):
        def handler(conn):
            events = []
            with self.lock:
                self.conns.append(events)
            try:
                up = socket.create_connection(dst, 5)
            except OSError:
                return
            events.append((now_ns(), "open", None))
            done = threading.Event()

            def pump(a, b, is_up):
                try:
                    while True:
                        data = a.recv(65536)
                        if not data:
                            break
                        with self.lock:
                            events.append((now_ns(), is_up, data))
                        b.sendall(data)
                except OSError:
                    pass
                with self.lock:
                    events.append((now_ns(), "fin", is_up))
                try:
                    b.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                done.set()

            threading.Thread(target=pump, args=(up, conn, False), daemon=True).start()
            pump(conn, up, True)
            done.wait(10)
            up.close()
        return handler


def ip_tcp(src, dst, sport, dport, seq, ack, flags, payload):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xffffffff, ack & 0xffffffff, 0x50, flags, 65535, 0, 0)
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 6, 0, src, dst)
    return ip + tcp + payload


def write_pcap(path, conns):
    frames = []
    for i, events in enumerate(conns):
        if not events:
            continue
        cport = 50000 + i
        cseq, sseq = 0x1000 + i * 7919, 0x7000000 + i * 104729
        t0 = events[0][0]
        frames.append((t0, ip_tcp(PCAP_CLIENT, PCAP_NODE, cport, 443, cseq, 0, 0x02, b"")))
        frames.append((t0 + 1000, ip_tcp(PCAP_NODE, PCAP_CLIENT, 443, cport, sseq, cseq + 1, 0x12, b"")))
        cseq += 1
        sseq += 1
        frames.append((t0 + 2000, ip_tcp(PCAP_CLIENT, PCAP_NODE, cport, 443, cseq, sseq, 0x10, b"")))
        for ns, kind, data in events[1:]:
            if kind == "fin":
                if data:
                    frames.append((ns, ip_tcp(PCAP_CLIENT, PCAP_NODE, cport, 443, cseq, sseq, 0x11, b"")))
                    cseq += 1
                else:
                    frames.append((ns, ip_tcp(PCAP_NODE, PCAP_CLIENT, 443, cport, sseq, cseq, 0x11, b"")))
                    sseq += 1
                continue
            # one recv may span several segments on a real link
            for off in range(0, len(data), 1448):
                part = data[off:off + 1448]
                if kind:
                    frames.append((ns, ip_tcp(PCAP_CLIENT, PCAP_NODE, cport, 443, cseq, sseq, 0x18, part)))
                    cseq += len(part)
                else:
                    frames.append((ns, ip_tcp(PCAP_NODE, PCAP_CLIENT, 443, cport, sseq, cseq, 0x18, part)))
                    sseq += len(part)
    frames.sort(key=lambda f: f[0])
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b23c4d, 2, 4, 0, 0, 65535, 101))
        for ns, pkt in frames:
            f.write(struct.pack("<IIII", ns // 1000000000, ns % 1000000000, len(pkt), len(pkt)))
            f.write(pkt)


# ---------------------------------------------------------------- xray

def xray_configs(crt, key):
    uid, pw = str(uuid.uuid4()), secrets.token_urlsafe(18)
    tls_in = {"certificates": [{"certificateFile": crt, "keyFile": key}]}
    server = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "vless", "protocol": "vless", "listen": NODE, "port": CASES["vless-tls"]["port"],
             "settings": {"clients": [{"id": uid}], "decryption": "none"},
             "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_in}},
            {"tag": "vision", "protocol": "vless", "listen": NODE, "port": CASES["vless-vision"]["port"],
             "settings": {"clients": [{"id": uid, "flow": "xtls-rprx-vision"}], "decryption": "none"},
             "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_in}},
            {"tag": "trojan", "protocol": "trojan", "listen": NODE, "port": CASES["trojan-tls"]["port"],
             "settings": {"clients": [{"password": pw}]},
             "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_in}},
        ],
        # xray 26 blocks private targets behind vless and trojan unless allowed
        "outbounds": [{"protocol": "freedom", "tag": "direct", "settings": {"finalRules": [
            {"action": "allow", "ip": [TARGET + "/32"], "port": "443"}]}}],
    }
    # xray 26 has no allowInsecure; pin the lab certificate
    with open(crt) as f:
        pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read())).hexdigest()
    tls_out = {"serverName": "lab-a.test", "pinnedPeerCertSha256": pin}
    stream = {"network": "tcp", "security": "tls", "tlsSettings": tls_out}
    relay = lambda case: {"address": RELAY, "port": CASES[case]["port"]}
    client = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "in-" + c, "protocol": "dokodemo-door", "listen": CLIENT, "port": CASES[c]["local"],
             "settings": {"address": TARGET, "port": 443, "network": "tcp"}}
            for c in ("vless-tls", "vless-vision", "trojan-tls")
        ],
        "outbounds": [
            {"tag": "out-vless-tls", "protocol": "vless", "streamSettings": stream,
             "settings": {"vnext": [dict(relay("vless-tls"), users=[{"id": uid, "encryption": "none"}])]}},
            {"tag": "out-vless-vision", "protocol": "vless", "streamSettings": stream,
             "settings": {"vnext": [dict(relay("vless-vision"),
                                         users=[{"id": uid, "encryption": "none", "flow": "xtls-rprx-vision"}])]}},
            {"tag": "out-trojan-tls", "protocol": "trojan", "streamSettings": stream,
             "settings": {"servers": [dict(relay("trojan-tls"), password=pw)]}},
        ],
        "routing": {"rules": [{"type": "field", "inboundTag": ["in-" + c], "outboundTag": "out-" + c}
                              for c in ("vless-tls", "vless-vision", "trojan-tls")]},
    }
    return server, client


def start_xray(xray, name, cfg):
    path = os.path.join(lab.RUN, name + ".json")
    with open(path, "w") as f:
        json.dump(cfg, f)
    logf = open(os.path.join(lab.RUN, name + ".log"), "w")
    p = subprocess.Popen([xray, "run", "-c", path], stdout=logf, stderr=subprocess.STDOUT,
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return p


# ---------------------------------------------------------------- inner client

def inner_session(addr, requests):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    with socket.create_connection(addr, 10) as raw:
        with ctx.wrap_socket(raw, server_hostname="lab-a.test") as t:
            t.settimeout(10)
            for i in range(requests):
                last = i == requests - 1
                t.sendall(b"GET /page/" + str(i).encode() + b" HTTP/1.1\r\nHost: lab-a.test\r\n"
                          b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) lab\r\nAccept: */*\r\n"
                          b"Accept-Language: en-US,en;q=0.9\r\nAccept-Encoding: identity\r\n"
                          # browser-sized: the plain case then passes the hello-size test
                          b"Cookie: session=" + COOKIE + b"\r\n" +
                          (b"Connection: close\r\n" if last else b"") + b"\r\n")
                got = b""
                while len(got) < len(PAGE):
                    chunk = t.recv(65536)
                    if not chunk:
                        break
                    got += chunk
                    if b"\r\n\r\n" in got and len(got) - got.index(b"\r\n\r\n") - 4 >= len(PAGE):
                        break


def record(outdir):
    """returns {case: pcap path}, {case: note} and the cases that could not run"""
    xray = lab.find_xray()
    if not xray:
        return {}, {}, list(CASES)
    os.makedirs(lab.RUN, exist_ok=True)
    os.makedirs(outdir, exist_ok=True)
    crt, key = lab.make_cert(xray, "lab-a.test")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    ctx.set_alpn_protocols(["http/1.1"])
    st = lab.Stand()
    recs = {c: Recorder() for c in CASES}
    before = len(lab.BIND_FAILED)
    st.listen_tcp(TARGET, 443, origin_handler_factory(ctx))
    for c, spec in CASES.items():
        dst = (TARGET, 443) if spec["local"] is None else (NODE, spec["port"])
        st.listen_tcp(RELAY, spec["port"], recs[c].relay_factory(dst))
    server, client = xray_configs(crt, key)
    procs = [start_xray(xray, "xray-cap-server", server), start_xray(xray, "xray-cap-client", client)]
    paths, notes, failed = {}, {}, []
    try:
        time.sleep(2.5)
        refused = lab.BIND_FAILED[before:]
        if any(p.poll() is not None for p in procs) or refused:
            return {}, {"start": "xray or a listener did not start: %s" % "; ".join(refused)}, list(CASES)
        for c, spec in CASES.items():
            addr = (RELAY, spec["port"]) if spec["local"] is None else (CLIENT, spec["local"])
            ok = 0
            for i in range(CONNECTIONS):
                try:
                    # plain https gets keep-alive, the tunnels one request each
                    inner_session(addr, 3 if spec["local"] is None else 1)
                    ok += 1
                except (OSError, ssl.SSLError) as e:
                    notes[c] = "connection %d: %s" % (i, e)
                time.sleep(0.3)
            time.sleep(0.5)
            if ok < 2:
                failed.append(c)
                continue
            path = os.path.join(outdir, c + ".pcap")
            with recs[c].lock:
                write_pcap(path, [list(e) for e in recs[c].conns])
            paths[c] = path
    finally:
        st.close()
        for p in procs:
            p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
    return paths, notes, failed


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(lab.RUN, "captures")
    paths, notes, failed = record(out)
    for c, p in paths.items():
        print("%-14s %s" % (c, p))
    for k, v in notes.items():
        lab.log("%s: %s" % (k, v))
    if failed:
        lab.log("not recorded: %s" % " ".join(failed))
    sys.exit(1 if failed else 0)
