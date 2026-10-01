# SPDX-License-Identifier: GPL-3.0-or-later
"""diff, batch input handling and pcap on files; no network. needs a built executable."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def report(target, label, ports, cert, check="negative"):
    return {
        "tool": "byebyevpn", "target": target, "resolved_ip": "203.0.113.5", "score": 50,
        "label": label, "unreliable": False, "tspu": {"tier": "PASS"},
        "checks": [{"id": "wg-family", "port": 51820, "outcome": check}],
        "signals": {"scored": []}, "geo": [],
        "open_tcp": [{"port": p} for p in ports], "udp": [],
        "tls_ports": [{"port": 443, "cert_sha256": cert, "cert_cn": target, "cert_issuer": "R11",
                       "tls_version": "TLSv1.3", "alpn": "h2", "utls": None}],
    }


def dns_capture(names):
    # raw ip pcap, one cleartext query per name
    out = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)
    for i, name in enumerate(names):
        q = struct.pack("!HHHHHH", i + 1, 0x0100, 1, 0, 0, 0)
        q += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00" + struct.pack("!HH", 1, 1)
        udp = struct.pack("!HHHH", 53000 + i, 53, 8 + len(q), 0) + q
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                         bytes([192, 0, 2, 10]), bytes([192, 0, 2, 1])) + udp
        out += struct.pack("<IIII", 1 + i, 0, len(ip), len(ip)) + ip
    return out


def main():
    exe = str(Path(sys.argv[1]).resolve())

    def run(args, code, as_json=True):
        r = subprocess.run([exe, *args, "--json" if as_json else "--no-color"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=20, stdin=subprocess.DEVNULL)
        assert r.returncode == code, (args, r.returncode, r.stdout[-800:], r.stderr[-800:])
        return json.loads(r.stdout) if as_json else r.stdout

    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        old, new = t / "old", t / "new"
        old.mkdir()
        new.mkdir()
        (old / "a.json").write_text(json.dumps(report("a.example", "CLEAN", [443], "aa")))
        (new / "a.json").write_text(json.dumps(report("a.example", "CLEAN", [443, 8443], "aa")))
        (old / "b.json").write_text(json.dumps(report("b.example", "CLEAN", [443], "bb")))
        (new / "b.json").write_text(json.dumps(report("b.example", "NOISY", [443], "bb", "positive")))
        (new / "c.json").write_text(json.dumps(report("c.example", "CLEAN", [443], "cc")))

        same = run(["diff", str(old / "a.json"), str(old / "a.json")], 0)
        assert same["pairs"][0]["changes"] == []
        surface = run(["diff", str(old / "a.json"), str(new / "a.json")], 1)
        assert surface["pairs"][0]["changes"] == [{"class": "surface", "what": "tcp 8443", "from": "", "to": "open"}]
        dirs = run(["diff", str(old), str(new)], 2)
        by = {p["name"]: p for p in dirs["pairs"]}
        assert set(by) == {"a.json", "b.json", "c.json"}
        assert by["b.json"]["exit"] == 2 and by["b.json"]["changes"][0]["class"] == "verdict"
        assert by["c.json"]["changes"][0]["what"] == "report" and by["c.json"]["target_b"] == "c.example"
        text = run(["diff", str(old), str(new)], 2, as_json=False)
        assert "CLEAN -> NOISY" in text
        # not a scan report, a missing file, the wrong arity
        (t / "pcap.json").write_text(json.dumps({"check": "pcap"}))
        assert not run(["diff", str(t / "pcap.json"), str(old / "a.json")], 64)["pairs"][0]["ok"]
        run(["diff", str(t / "missing.json"), str(old / "a.json")], 64)
        run(["diff", str(old / "a.json")], 64, as_json=False)

        # batch refuses bad lists before it scans anything
        (t / "empty.txt").write_text("# nothing\n\n")
        run(["batch", str(t / "empty.txt")], 64, as_json=False)
        (t / "bad.txt").write_text("node.example extra\n")
        run(["batch", str(t / "bad.txt")], 64, as_json=False)
        run(["batch", str(t / "missing.txt")], 64, as_json=False)

        # pcap on a capture with two cleartext queries
        (t / "dns.pcap").write_bytes(dns_capture(["example.com", "node.example.net"]))
        cap = run(["pcap", str(t / "dns.pcap")], 2)
        assert cap["dns"]["outcome"] == "positive" and cap["dns"]["queries"] == 2
        assert cap["outside_node"]["outcome"] == "not applicable"
        (t / "junk.pcap").write_bytes(b"\x00" * 64)
        assert run(["pcap", str(t / "junk.pcap")], 64)["error"]
    print("offline cli: ok")


if __name__ == "__main__":
    main()
