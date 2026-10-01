# SPDX-License-Identifier: GPL-3.0-or-later
"""Loopback checks for `dpi`: reply, reset and silent drop of one SNI."""
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

ALERT = bytes([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])


def serve(listener, mode, stop):
    # alert on any hello except one carrying "localhost"
    while not stop.is_set():
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(2)
            data = b""
            try:
                while len(data) < 5 or len(data) < 5 + int.from_bytes(data[3:5], "big"):
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            if b"localhost" not in data or mode == "reply":
                conn.sendall(ALERT)
            elif mode == "silent":
                time.sleep(4)


def run(exe, mode):
    stop = threading.Event()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        listener.settimeout(20)
        port = listener.getsockname()[1]
        worker = threading.Thread(target=serve, args=(listener, mode, stop), daemon=True)
        worker.start()
        try:
            result = subprocess.run([exe, "--no-color", "dpi", "localhost", str(port)],
                                    capture_output=True, text=True, encoding="utf-8", timeout=60)
        finally:
            stop.set()
    return result.returncode, result.stdout


def main():
    exe = str(Path(sys.argv[1]).resolve())
    code, out = run(exe, "reply")
    assert code == 0 and "target-SNI: ok" in out, (code, out)
    code, out = run(exe, "silent")
    assert code == 2 and "target-SNI: silent" in out and "SNI-specific" in out, (code, out)
    assert "the ClientHello reached the host and got a TLS reply" not in out, out
    code, out = run(exe, "reset")
    assert code == 2 and "target-SNI: RESET" in out, (code, out)
    print("dpi loopback regressions passed (reply, silent drop, reset)")


if __name__ == "__main__":
    main()
