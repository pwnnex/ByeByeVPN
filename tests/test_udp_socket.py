# SPDX-License-Identifier: GPL-3.0-or-later
"""Loopback integration checks for the Windows UDP probe."""
from pathlib import Path
import socket
import subprocess
import sys


def main():
    exe = str(Path(sys.argv[1]).resolve())
    for case in ("foreign", "valid", "empty", "echo", "large"):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as foreign:
            peer.bind(("127.0.0.1", 0))
            foreign.bind(("127.0.0.1", 0))
            peer.settimeout(5)
            child = subprocess.Popen([exe, str(peer.getsockname()[1])], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, encoding="utf-8")
            try:
                payload, target = peer.recvfrom(1024)
                assert payload == b"0123456789abcdef"
                foreign.sendto(b"wrong-endpoint", target)
                if case == "valid": peer.sendto(b"correct-peer", target)
                if case == "empty": peer.sendto(b"", target)
                if case == "echo": peer.sendto(payload, target)
                if case == "large": peer.sendto(b"L" * 4096, target)
                stdout, stderr = child.communicate(timeout=5)
                assert child.returncode == 0, (stdout, stderr)
                lines = stdout.splitlines()
                responded, size, echoed = map(int, lines[0].split())
                if case == "foreign":
                    assert responded == 0 and "no-reply" in stdout, stdout
                elif case == "valid":
                    assert (responded, size, echoed) == (1, 12, 0), stdout
                    assert "63 6f 72 72 65 63 74 2d 70 65 65 72" == lines[1].lower(), stdout
                elif case == "empty": assert (responded, size, echoed) == (1, 0, 0), stdout
                elif case == "echo": assert (responded, size, echoed) == (1, 16, 1), stdout
                elif case == "large":
                    assert (responded, size, echoed) == (1, 2048, 0) and "truncated" in stdout, stdout
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate()
    print("UDP loopback regressions passed (foreign source, valid, empty, echo, oversized reply)")


if __name__ == "__main__":
    main()
