# SPDX-License-Identifier: GPL-3.0-or-later
"""ground-truth stands on loopback, one 127.0.1.x address per stand.

python stands mimic a plain web origin, an ack-all middlebox, a lossy path and
synthetic udp responders. xray stands are the real server implementations.
secrets live in .run/ and are never printed.
"""
import base64
import json
import os
import random
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
RUN = os.path.join(HERE, ".run")

# ports every scan gets, so stands are compared on the same probe set.
# 1000-1099 make an ack-all host cross the >60 open-port heuristic.
# plain http sits on 8000: ci runners hold 22 and 80 with system services
HTTP_PORT = 8000
SCAN_PORTS = [HTTP_PORT, 443, 4711, 8080, 8388, 8443, 10808] + list(range(1000, 1100))

# truth per stand. vpn: a tunnel or proxy really listens there.
# detectable: signal ids that may honestly fire on this stand.
# labels: acceptable verdict labels. synthetic: parser test, not a real server.
# quic: a real quic stack answers there. needs: process the stand cannot run without.
STANDS = {
    "A": dict(ip="127.0.1.1", vpn=False, detectable=set(), labels={"CLEAN"},
              what="plain TLS web origin on :443 and HTTP on :8000"),
    "B": dict(ip="127.0.1.2", vpn=False, detectable=set(), labels={"CLEAN", "NOISY"},
              what="same origin on nonstandard :4711 only"),
    "C": dict(ip="127.0.1.3", vpn=True, detectable=set(), labels={"CLEAN", "NOISY", "INCONCLUSIVE"},
              what="xray VLESS+Reality on :443, target = stand A", needs="xray"),
    "D": dict(ip="127.0.1.4", vpn=True, detectable=set(), labels={"CLEAN", "NOISY", "SUSPICIOUS", "INCONCLUSIVE"},
              what="xray VLESS+Reality on :443, target = www.microsoft.com:443", needs="xray"),
    "E": dict(ip="127.0.1.5", vpn=True, detectable=set(), labels={"CLEAN", "NOISY", "INCONCLUSIVE"},
              what="xray Shadowsocks aes-256-gcm on :8388", needs="xray"),
    "F": dict(ip="127.0.1.6", vpn=True, detectable=set(), labels={"INCONCLUSIVE"},
              what="WireGuard on udp :51820 (xray inbound or silent listener), no tcp", needs="xray"),
    "H1": dict(ip="127.0.1.8", vpn=False, detectable=set(), labels={"INCONCLUSIVE"},
               what="nothing listens, every port answers RST"),
    "H2": dict(ip="192.0.2.1", vpn=False, detectable=set(), labels={"INCONCLUSIVE"},
               what="TEST-NET-1, packets vanish, nothing answers"),
    "I": dict(ip="127.0.1.9", vpn=False, detectable=set(), labels={"INCONCLUSIVE"},
              what="ack-all middlebox: every scanned tcp port accepts and stays silent"),
    "J": dict(ip="127.0.1.10", vpn=False, detectable=set(), labels={"CLEAN", "NOISY", "INCONCLUSIVE"},
              what="stand A behind a lossy relay: 30% of connections stall, 0-150 ms jitter"),
    "K": dict(ip="127.0.1.14", vpn=False, detectable=set(), labels={"CLEAN", "NOISY", "INCONCLUSIVE"},
              what="udp traps: :51820 answers 92 B type-2 garbage unrelated to the probe, :55555 echoes"),
    "S": dict(ip="127.0.1.11", vpn=True, detectable={"socks5"}, labels={"NOISY", "SUSPICIOUS", "OBVIOUSLY-VPN"},
              what="xray SOCKS5 no-auth on :10808 plus plain HTTP on :8000", needs="xray"),
    "W": dict(ip="127.0.1.13", vpn=True, detectable={"wg-family"}, labels={"NOISY", "SUSPICIOUS", "OBVIOUSLY-VPN", "INCONCLUSIVE"},
              what="synthetic WireGuard responder: valid 92 B response to the probe's sender index",
              synthetic=True),
    "G": dict(ip="127.0.1.16", vpn=True, detectable={"wg-family"}, labels={"NOISY", "SUSPICIOUS", "OBVIOUSLY-VPN", "INCONCLUSIVE"},
              what="synthetic AmneziaWG S1=8 S2=16 responder on udp :51820",
              synthetic=True),
    "X": dict(ip="127.0.1.15", vpn=True, detectable={"sstp"}, labels={"NOISY", "SUSPICIOUS", "OBVIOUSLY-VPN"},
              what="synthetic SSTP setup responder on :443",
              synthetic=True),
    # no tcp service: an honest scan has nothing to attribute and refuses a verdict
    "Q": dict(ip="127.0.1.17", vpn=True, detectable=set(), labels={"CLEAN", "NOISY", "INCONCLUSIVE"},
              what="xray Hysteria2 (quic v1, tls alpn h3) on udp :443, no tcp", quic=True,
              needs="xray-hysteria"),
    "U": dict(ip="127.0.1.18", vpn=False, detectable=set(), labels={"CLEAN", "NOISY", "INCONCLUSIVE"},
              what="quic-shaped udp traps: :443 answers a v1 Initial for a foreign connection id, "
                   ":8443 answers version negotiation with the ids swapped wrong"),
    # owner self-check: the same addresses scanned with --wg-pubkey / --wg-key
    "FK": dict(ip="127.0.1.6", vpn=True, detectable={"wg-keyed"}, labels={"NOISY", "SUSPICIOUS", "OBVIOUSLY-VPN"},
               what="stand F with the server key and a configured peer key", keyed="peer", needs="xray-wg"),
    "FS": dict(ip="127.0.1.6", vpn=True, detectable={"wg-keyed"}, labels={"NOISY", "SUSPICIOUS", "OBVIOUSLY-VPN"},
               what="stand F, right keys, a preshared key the server does not have", keyed="psk", needs="xray-wg"),
    "FW": dict(ip="127.0.1.6", vpn=True, detectable=set(), labels={"INCONCLUSIVE"},
               what="stand F with the server key and a peer key the server does not know", keyed="stranger",
               needs="xray-wg"),
    "WK": dict(ip="127.0.1.13", vpn=True, detectable={"wg-family"}, labels={"NOISY", "SUSPICIOUS", "OBVIOUSLY-VPN", "INCONCLUSIVE"},
               what="stand W with keys: copies our index, cannot produce mac1", keyed="peer", synthetic=True,
               needs="xray"),
    "KK": dict(ip="127.0.1.14", vpn=False, detectable=set(), labels={"CLEAN", "NOISY", "INCONCLUSIVE"},
               what="stand K with keys: unrelated type-2 garbage", keyed="peer", needs="xray"),
}

# key files written by start_all; paths only ever reach the scanner's argv
WG_FILES = {k: os.path.join(RUN, v) for k, v in
            dict(pub="wg-server.pub", peer="wg-peer.key", stranger="wg-stranger.key", psk="wg-psk-other.key").items()}


def keyed_args(kind):
    if not kind:
        return []
    key = WG_FILES["stranger"] if kind == "stranger" else WG_FILES["peer"]
    if kind == "psk":
        # public key as text, the other runs read it from a file
        with open(WG_FILES["pub"]) as f:
            return ["--wg-pubkey", f.read().strip(), "--wg-key", key, "--wg-psk", WG_FILES["psk"]]
    return ["--wg-pubkey", WG_FILES["pub"], "--wg-key", key]

# stands whose process did not start this run; run.py skips them
DISABLED = set()
# "ip:port/proto error" for every listener the host refused
BIND_FAILED = []

# dpi --sni --real: a node behind a box that drops one name, the real site
# that serves it, and a real site that drops it too. not scanned.
SNI_NAME = "brand.lab.test"
SNI_SERVERS = {
    "N":  dict(ip="127.0.1.24", gate=True,  what="node: drops %s silently, answers every other name" % SNI_NAME),
    "R":  dict(ip="127.0.1.25", gate=False, what="the real site: answers %s" % SNI_NAME),
    "RB": dict(ip="127.0.1.26", gate=True,  what="a real site that drops %s too" % SNI_NAME),
}

# tls servers for the client-side volume check (dpi --volume), not scanned.
# body sizes are app bytes; the client counts socket bytes, handshake included
VOLUME_SERVERS = {
    "V":  dict(ip="127.0.1.19", mode="fast",   what="256 KB with Content-Length, no pause"),
    "V2": dict(ip="127.0.1.21", mode="fast",   what="same as V, the control host"),
    "Z":  dict(ip="127.0.1.20", mode="freeze", what="14000 B of body, then silence on an open connection (F7 emulation)"),
    "Y":  dict(ip="127.0.1.22", mode="pause",  what="16 KB, a 3 s pause right in the freeze band, then the rest"),
    "T":  dict(ip="127.0.1.23", mode="close",  what="14000 B of body, then FIN"),
}

XRAY_CANDIDATES = [
    os.environ.get("BBV_XRAY", ""),
    os.path.join(HERE, "bin", "xray.exe"),
    shutil.which("xray") or "",
]


def log(msg):
    print("[lab] " + msg, file=sys.stderr, flush=True)


def find_xray():
    for p in XRAY_CANDIDATES:
        if p and os.path.isfile(p):
            return os.path.abspath(p)
    return None


# ---------------------------------------------------------------- tcp stands

class Stand:
    """collects listening sockets and worker threads, stops them all at once."""

    def __init__(self):
        self.stop = threading.Event()
        self.socks = []

    def listen_tcp(self, ip, port, handler):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((ip, port))
        except OSError as e:
            # a port taken on the host must not kill every stand
            s.close()
            BIND_FAILED.append("%s:%d/tcp %s" % (ip, port, e))
            return
        s.listen(128)
        s.settimeout(0.5)
        self.socks.append(s)

        def loop():
            while not self.stop.is_set():
                try:
                    c, _ = s.accept()
                except OSError:
                    continue
                threading.Thread(target=self._guard, args=(handler, c), daemon=True).start()
        threading.Thread(target=loop, daemon=True).start()

    def listen_udp(self, ip, port, handler):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind((ip, port))
        except OSError as e:
            s.close()
            BIND_FAILED.append("%s:%d/udp %s" % (ip, port, e))
            return
        s.settimeout(0.5)
        self.socks.append(s)

        def loop():
            while not self.stop.is_set():
                try:
                    data, peer = s.recvfrom(4096)
                except OSError:
                    continue
                try:
                    out = handler(data)
                    if out is not None:
                        s.sendto(out, peer)
                except Exception:
                    pass
        threading.Thread(target=loop, daemon=True).start()

    @staticmethod
    def _guard(handler, c):
        try:
            handler(c)
        except Exception:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    def close(self):
        self.stop.set()
        for s in self.socks:
            try:
                s.close()
            except OSError:
                pass


def read_head(conn, limit=16384, timeout=3.0):
    conn.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < limit:
        try:
            chunk = conn.recv(4096)
        except (socket.timeout, OSError, ssl.SSLError):
            break
        if not chunk:
            break
        buf += chunk
    return buf


METHODS = {b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"OPTIONS", b"PATCH", b"CONNECT"}
PAGE = b"<!doctype html><html><head><title>lab</title></head><body>ok</body></html>\n"


def http_reply(head):
    # nginx-shaped answers: 400 on junk, 405 on methods a static site refuses
    line = head.split(b"\r\n", 1)[0]
    parts = line.split(b" ")
    if len(parts) != 3 or not parts[2].startswith(b"HTTP/1."):
        status, body = b"400 Bad Request", b"<html><body>400 Bad Request</body></html>\n"
    elif parts[0] not in METHODS:
        status, body = b"405 Not Allowed", b"<html><body>405 Not Allowed</body></html>\n"
    elif parts[0] == b"CONNECT":
        status, body = b"400 Bad Request", b"<html><body>400 Bad Request</body></html>\n"
    else:
        status, body = b"200 OK", PAGE
    hdr = (b"HTTP/1.1 " + status + b"\r\nServer: nginx\r\nContent-Type: text/html\r\n"
           b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n")
    return hdr + (b"" if parts[0] == b"HEAD" else body)


def plain_http_handler(conn):
    head = read_head(conn)
    if head:
        conn.sendall(http_reply(head))


def tls_handler_factory(ctx, sstp=False):
    def handler(conn):
        conn.settimeout(5)
        try:
            t = ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            return
        head = read_head(t)
        if not head:
            return
        if sstp and head.startswith(b"SSTP_DUPLEX_POST "):
            # ms-sstp 3.2.4.1: 200 with the magic content-length
            t.sendall(b"HTTP/1.1 200\r\nContent-Length: 18446744073709551615\r\n"
                      b"Server: Microsoft-HTTPAPI/2.0\r\nDate: Thu, 01 Jan 2026 00:00:00 GMT\r\n\r\n")
            time.sleep(1)
            return
        t.sendall(http_reply(head))
        try:
            t.unwrap()
        except (ssl.SSLError, OSError):
            pass
    return handler


def volume_handler_factory(ctx, mode):
    chunk = secrets.token_bytes(16384)
    total = 256 * 1024

    def send_body(t, n):
        while n > 0:
            part = chunk[:min(n, len(chunk))]
            t.sendall(part)
            n -= len(part)

    def handler(conn):
        conn.settimeout(30)
        try:
            t = ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            return
        if not read_head(t):
            return
        t.sendall(b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/octet-stream\r\n"
                  b"Content-Length: " + str(total).encode() + b"\r\nConnection: close\r\n\r\n")
        if mode == "fast":
            send_body(t, total)
        elif mode == "pause":
            send_body(t, 16384)
            time.sleep(3)
            send_body(t, total - 16384)
        elif mode == "freeze":
            send_body(t, 14000)
            # hold the connection without a byte, as the box does
            time.sleep(20)
            return
        elif mode == "close":
            send_body(t, 14000)
            return
        try:
            t.unwrap()
        except (ssl.SSLError, OSError):
            pass
    return handler


def peek_sni(conn):
    # rfc 8446 4.1.2 clienthello, read without consuming it
    conn.settimeout(5)
    try:
        d = conn.recv(4096, socket.MSG_PEEK)
    except OSError:
        return None
    try:
        if len(d) < 44 or d[0] != 0x16 or d[5] != 0x01:
            return None
        p = 43
        p += 1 + d[p]
        p += 2 + int.from_bytes(d[p:p + 2], "big")
        p += 1 + d[p]
        end = p + 2 + int.from_bytes(d[p:p + 2], "big")
        p += 2
        while p + 4 <= end:
            t, n = int.from_bytes(d[p:p + 2], "big"), int.from_bytes(d[p + 2:p + 4], "big")
            p += 4
            if t == 0:
                size = int.from_bytes(d[p + 3:p + 5], "big")
                return d[p + 5:p + 5 + size].decode("ascii", "replace")
            p += n
    except (IndexError, ValueError):
        return None
    return None


def sni_gate_factory(ctx, blocked):
    # a path box that drops one name silently, the way tspu does
    web = tls_handler_factory(ctx)

    def handler(conn):
        if peek_sni(conn) == blocked:
            silent_handler(conn)
            return
        web(conn)
    return handler


def silent_handler(conn):
    # ack-all: take bytes, never answer, hold the socket like a middlebox
    conn.settimeout(8)
    try:
        while conn.recv(4096):
            pass
    except (socket.timeout, OSError):
        pass


def lossy_relay_factory(dst, loss=0.30, jitter_ms=150):
    def handler(conn):
        rnd = random.SystemRandom()
        time.sleep(rnd.uniform(0, jitter_ms) / 1000.0)
        if rnd.random() < loss:
            silent_handler(conn)
            return
        up = socket.create_connection(dst, timeout=5)
        stop = threading.Event()

        def pump(a, b):
            try:
                while not stop.is_set():
                    d = a.recv(16384)
                    if not d:
                        break
                    b.sendall(d)
            except OSError:
                pass
            finally:
                stop.set()
        th = threading.Thread(target=pump, args=(up, conn), daemon=True)
        th.start()
        pump(conn, up)
        th.join(5)
        up.close()
    return handler


# ---------------------------------------------------------------- udp stands

def wg_responder(data):
    # whitepaper 5.4.2 initiation is 148 B; answer with a 5.4.3 response
    if len(data) != 148 or data[0] != 1 or data[1:4] != b"\0\0\0":
        return None
    return b"\x02\0\0\0" + secrets.token_bytes(4) + data[4:8] + secrets.token_bytes(80)


def awg_responder_factory(s1=8, s2=16):
    def h(data):
        if len(data) != s1 + 148 or data[s1] != 1:
            return None
        body = b"\x02\0\0\0" + secrets.token_bytes(4) + data[s1 + 4:s1 + 8] + secrets.token_bytes(80)
        return secrets.token_bytes(s2) + body
    return h


def unrelated_type2(data):
    # 92 B that parse as a response header but ignore the probe entirely
    return b"\x02\0\0\0" + secrets.token_bytes(88)


def quic_ids(data):
    # rfc 8999 5.1 invariant long header: version, dcid, scid
    if len(data) < 1200 or not data[0] & 0x80:
        return None
    dl = data[5]
    sl = data[6 + dl]
    return data[6:6 + dl], data[7 + dl:7 + dl + sl]


def quic_foreign_initial(data):
    # well-formed v1 Initial, addressed to ids the probe never chose
    if quic_ids(data) is None:
        return None
    body = secrets.token_bytes(1100)
    return (b"\xc0\0\0\0\x01" + b"\x08" + secrets.token_bytes(8) + b"\x08" + secrets.token_bytes(8) +
            b"\x00" + (0x4000 | len(body)).to_bytes(2, "big") + body)


def quic_vn_swapped(data):
    # rfc 9000 17.2.1 wants dcid = client scid; this echoes the client dcid there
    ids = quic_ids(data)
    if ids is None:
        return None
    dcid, scid = ids
    return (bytes([0x80 | secrets.randbelow(128)]) + b"\0\0\0\0" + bytes([len(dcid)]) + dcid +
            bytes([len(scid)]) + scid + b"\0\0\0\x01")


def echo(data):
    return data


def udp_sink(data):
    return None


# ---------------------------------------------------------------- xray

def xray_out(xray, *args):
    r = subprocess.run([xray, *args], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError("xray %s failed" % args[0])
    return r.stdout


def keypair(text, priv_label, pub_labels):
    priv = pub = None
    for line in text.splitlines():
        k, _, v = line.partition(":")
        # xray 26 prints "Password (PublicKey)"
        k = re.sub(r"\(.*\)", "", k).strip().lower().replace(" ", "")
        if k == priv_label:
            priv = v.strip()
        elif k in pub_labels:
            pub = v.strip()
    if not priv or not pub:
        raise RuntimeError("cannot parse xray key output")
    return priv, pub


def make_cert(xray, domain):
    path = os.path.join(RUN, domain)
    if not os.path.isfile(path + ".crt"):
        # default org is "Xray Inc", which would plant a vpn marker in a clean stand
        out = xray_out(xray, "tls", "cert", "-domain=" + domain, "-name=" + domain,
                       "-org=Lab Origin", "-expire=2160h", "-json")
        j = json.loads(out)
        with open(path + ".crt", "w") as f:
            f.write("\n".join(j["certificate"]) + "\n")
        # xray labels its ec key as rsa, openssl refuses that
        key = "\n".join(j["key"]).replace("RSA PRIVATE KEY", "EC PRIVATE KEY")
        with open(path + ".key", "w") as f:
            f.write(key + "\n")
    return path + ".crt", path + ".key"


def write_secret(path, text):
    with open(path, "w") as f:
        f.write(text + "\n")


def xray_config(xray, wg_inbound=True):
    rpriv, _ = keypair(xray_out(xray, "x25519"), "privatekey", {"password", "publickey"})
    wpriv, wpub = keypair(xray_out(xray, "wg"), "privatekey", {"password", "publickey"})
    peer_priv, peer_pub = keypair(xray_out(xray, "wg"), "privatekey", {"password", "publickey"})
    stranger_priv, _ = keypair(xray_out(xray, "wg"), "privatekey", {"password", "publickey"})
    write_secret(WG_FILES["pub"], wpub)
    write_secret(WG_FILES["peer"], peer_priv)
    write_secret(WG_FILES["stranger"], stranger_priv)
    write_secret(WG_FILES["psk"], base64.b64encode(secrets.token_bytes(32)).decode())
    uid = str(uuid.uuid4())
    reality = lambda ip, target, names: {
        "tag": "reality-" + ip, "protocol": "vless", "listen": ip, "port": 443,
        "settings": {"clients": [{"id": uid, "flow": "xtls-rprx-vision"}], "decryption": "none"},
        "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
            "target": target, "serverNames": names, "privateKey": rpriv, "shortIds": ["", secrets.token_hex(4)]}},
    }
    inb = [
        reality(STANDS["C"]["ip"], STANDS["A"]["ip"] + ":443", ["lab-a.test"]),
        reality(STANDS["D"]["ip"], "www.microsoft.com:443", ["www.microsoft.com"]),
        {"tag": "ss", "protocol": "shadowsocks", "listen": STANDS["E"]["ip"], "port": 8388,
         "settings": {"method": "aes-256-gcm", "password": secrets.token_urlsafe(24), "network": "tcp,udp"}},
        {"tag": "socks", "protocol": "socks", "listen": STANDS["S"]["ip"], "port": 10808,
         "settings": {"auth": "noauth", "udp": False}},
    ]
    if wg_inbound:
        inb.append({"tag": "wg", "protocol": "wireguard", "listen": STANDS["F"]["ip"], "port": 51820,
                    "settings": {"secretKey": wpriv, "peers": [{"publicKey": peer_pub, "allowedIPs": ["10.77.0.2/32"]}]}})
    return {
        "log": {"loglevel": "warning"},
        "inbounds": inb,
        # nothing relays anywhere; the lab only needs the handshakes
        "outbounds": [{"protocol": "blackhole", "tag": "block"}],
    }


def start_xray(xray):
    for wg in (True, False):
        cfg = os.path.join(RUN, "xray.json")
        with open(cfg, "w") as f:
            json.dump(xray_config(xray, wg), f)
        logf = open(os.path.join(RUN, "xray.log"), "w")
        p = subprocess.Popen([xray, "run", "-c", cfg], stdout=logf, stderr=subprocess.STDOUT,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        time.sleep(2.5)
        if p.poll() is None:
            return p, wg
        log("xray exited with wireguard inbound=%s, see .run/xray.log" % wg)
    raise RuntimeError("xray does not start")


def start_hysteria(xray, crt, key):
    # own process: an xray without hysteria must not take the other stands down
    cfg = os.path.join(RUN, "xray-hy.json")
    with open(cfg, "w") as f:
        json.dump({
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "tag": "hy2", "protocol": "hysteria", "listen": STANDS["Q"]["ip"], "port": 443,
                "settings": {"version": 2, "clients": [{"auth": secrets.token_urlsafe(24)}]},
                "streamSettings": {"network": "hysteria", "security": "tls", "tlsSettings": {
                    "alpn": ["h3"], "certificates": [{"certificateFile": crt, "keyFile": key}]}},
            }],
            "outbounds": [{"protocol": "blackhole", "tag": "block"}],
        }, f)
    logf = open(os.path.join(RUN, "xray-hy.log"), "w")
    p = subprocess.Popen([xray, "run", "-c", cfg], stdout=logf, stderr=subprocess.STDOUT,
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    time.sleep(2.0)
    if p.poll() is None:
        return p
    log("xray hysteria inbound did not start, see .run/xray-hy.log")
    return None


# ---------------------------------------------------------------- bring-up

def start_all(with_xray=True):
    os.makedirs(RUN, exist_ok=True)
    st = Stand()
    xray = find_xray()
    procs = []
    notes = {}
    DISABLED.clear()
    del BIND_FAILED[:]
    if not xray:
        with_xray = False
    if not with_xray:
        DISABLED.update(n for n, s in STANDS.items() if s.get("needs", "").startswith("xray"))
        notes["xray"] = "xray.exe unavailable, stands %s disabled" % " ".join(sorted(DISABLED))
    crt_a = key_a = None
    if xray:
        crt_a, key_a = make_cert(xray, "lab-a.test")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["http/1.1"])
    if crt_a:
        ctx.load_cert_chain(crt_a, key_a)
    web = tls_handler_factory(ctx)
    sstp = tls_handler_factory(ctx, sstp=True)

    a, b = STANDS["A"]["ip"], STANDS["B"]["ip"]
    if crt_a:
        st.listen_tcp(a, 443, web)
        st.listen_tcp(b, 4711, web)
        st.listen_tcp(STANDS["X"]["ip"], 443, sstp)
        for v in VOLUME_SERVERS.values():
            st.listen_tcp(v["ip"], 443, volume_handler_factory(ctx, v["mode"]))
        for v in SNI_SERVERS.values():
            st.listen_tcp(v["ip"], 443, sni_gate_factory(ctx, SNI_NAME) if v["gate"] else web)
    else:
        DISABLED.update(("VOLUME", "SNI"))
    st.listen_tcp(a, HTTP_PORT, plain_http_handler)
    st.listen_tcp(STANDS["S"]["ip"], HTTP_PORT, plain_http_handler)

    ip_i = STANDS["I"]["ip"]
    for p in SCAN_PORTS:
        st.listen_tcp(ip_i, p, silent_handler)
    # hyper-v hosts reserve port blocks; I only needs >60 open filler ports
    filler = [b for b in BIND_FAILED if b.startswith(ip_i + ":") and 1000 <= int(b.split(":")[1].split("/")[0]) < 1100]
    if filler and len(SCAN_PORTS) - len(filler) > 70:
        for b in filler:
            BIND_FAILED.remove(b)
        notes["I"] = "%d filler ports refused by the host, %d open" % (len(filler), len(SCAN_PORTS) - len(filler))

    ip_j = STANDS["J"]["ip"]
    st.listen_tcp(ip_j, 443, lossy_relay_factory((a, 443)))
    st.listen_tcp(ip_j, HTTP_PORT, lossy_relay_factory((a, HTTP_PORT)))

    st.listen_udp(STANDS["W"]["ip"], 51820, wg_responder)
    st.listen_udp(STANDS["G"]["ip"], 51820, awg_responder_factory())
    st.listen_udp(STANDS["K"]["ip"], 51820, unrelated_type2)
    st.listen_udp(STANDS["K"]["ip"], 55555, echo)
    st.listen_udp(STANDS["U"]["ip"], 443, quic_foreign_initial)
    st.listen_udp(STANDS["U"]["ip"], 8443, quic_vn_swapped)

    if with_xray:
        p, wg = start_xray(xray)
        procs.append(p)
        notes["F"] = "xray wireguard inbound" if wg else "silent udp listener (xray wireguard inbound unavailable)"
        if not wg:
            st.listen_udp(STANDS["F"]["ip"], 51820, udp_sink)
            DISABLED.update(n for n, s in STANDS.items() if s.get("needs") == "xray-wg")
        hy = start_hysteria(xray, crt_a, key_a)
        if hy:
            procs.append(hy)
        else:
            DISABLED.add("Q")
            notes["Q"] = "disabled, this xray has no hysteria inbound"
    if BIND_FAILED:
        bad = {b.split(":", 1)[0] for b in BIND_FAILED}
        DISABLED.update(n for n, s in STANDS.items() if s["ip"] in bad)
        if any(v["ip"] in bad for v in VOLUME_SERVERS.values()):
            DISABLED.add("VOLUME")
        if any(v["ip"] in bad for v in SNI_SERVERS.values()):
            DISABLED.add("SNI")
        notes["bind failed"] = "; ".join(BIND_FAILED)
    return st, procs, notes


def stop_all(st, procs):
    st.close()
    for p in procs:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()


if __name__ == "__main__":
    st, procs, notes = start_all()
    for k, v in notes.items():
        log("%s: %s" % (k, v))
    for name, s in STANDS.items():
        log("%-3s %-11s %s" % (name, s["ip"], s["what"]))
    log("up; ctrl-c to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    stop_all(st, procs)
