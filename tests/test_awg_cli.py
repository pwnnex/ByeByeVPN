"""offline cli checks; synthetic traffic only.

usage: python tests/test_awg_cli.py ./byebyevpn.exe
"""
import json
import pathlib
import random
import struct
import subprocess
import sys
import tempfile


def frame(payload, reverse=False):
    a, b = bytes([192, 0, 2, 1]), bytes([203, 0, 113, 1])
    if reverse:
        a, b = b, a
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(payload), 0, 0, 64, 17, 0, a, b)
    ports = (443, 1234) if reverse else (1234, 443)
    udp = struct.pack("!HHHH", *ports, 8 + len(payload), 0)
    return bytes(12) + b"\x08\x00" + ip + udp + payload


def block(kind, data):
    data += bytes((-len(data)) % 4)
    size = len(data) + 12
    return struct.pack("<II", kind, size) + data + struct.pack("<I", size)


def capture(packets, ng):
    if ng:
        out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        out += block(1, struct.pack("<HHI", 1, 0, 65535))
        for ms, data in packets:
            ticks = ms * 1000  # default pcapng microsecond resolution
            out += block(6, struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xffffffff, len(data), len(data)) + data)
        return out
    out = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ms, data in packets:
        out += struct.pack("<IIII", ms // 1000, (ms % 1000) * 1000, len(data), len(data)) + data
    return out


def main():
    exe = str(pathlib.Path(sys.argv[1]).resolve())
    rng = random.Random(31)
    packets = []
    for base in (0, 20000):
        for i in range(5):
            packets.append((base+i, frame(rng.randbytes(220+i*113+base//100))))
        for j in range(14):
            packets.append((base+30+j*20, frame(rng.randbytes(200+j*23), j%2 == 0)))
    with tempfile.TemporaryDirectory(prefix="awg-cli-") as directory:
        root = pathlib.Path(directory)
        for ng in (False, True):
            path = root / ("outer.pcapng" if ng else "outer.pcap")
            path.write_bytes(capture(packets, ng))
            p = subprocess.run([exe, "awg-entropy", str(path), "--json"], capture_output=True, timeout=20)
            assert p.returncode == 0, p.stderr.decode(errors="replace")
            report = json.loads(p.stdout)
            assert report["ok"] and not report["protocol_confirmed"]
            assert report["udp_packets"] == 38
            assert report["flows"][0]["verdict"] == "AWG_COMPATIBLE_HEURISTIC"
            assert report["flows"][0]["awg_version"] == "unknown"
            text = subprocess.run([exe, "awg-entropy", str(path), "--no-color"], capture_output=True, timeout=20)
            assert text.returncode == 0 and b"AWG_COMPATIBLE_HEURISTIC" in text.stdout
        negative = root / "random-udp.pcap"
        negative.write_bytes(capture([(i*20,frame(rng.randbytes(256),i%2 == 0)) for i in range(80)],False))
        p = subprocess.run([exe,"awg-entropy",str(negative),"--json"],capture_output=True,timeout=20)
        assert json.loads(p.stdout)["flows"][0]["verdict"] == "ENCRYPTED_UDP_INCONCLUSIVE"
        bad = root / "bad.pcapng"
        bad.write_bytes(b"broken")
        for path in (bad, root / "absent.pcap"):
            p = subprocess.run([exe,"awg-entropy",str(path),"--json"],capture_output=True,timeout=20)
            assert p.returncode == 64
            report = json.loads(p.stdout)
            assert not report["ok"] and report["error"] and not report["flows"]
    print("AWG CLI: PCAP, PCAPNG, text/JSON, negative traffic and input errors passed")


if __name__ == "__main__":
    main()
