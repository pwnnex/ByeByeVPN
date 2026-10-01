# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline names command regressions; requires a built executable."""
import json
from pathlib import Path
import subprocess
import sys


def main():
    exe = str(Path(sys.argv[1]).resolve())

    def run(names, code, as_json=True, command="names"):
        result = subprocess.run([exe, command, *names, "--json" if as_json else "--no-color"],
                                capture_output=True, text=True, encoding="utf-8", timeout=10)
        assert result.returncode == code, (result.returncode, result.stdout, result.stderr)
        if not as_json:
            return result.stdout
        report = json.loads(result.stdout)
        assert report["network_checked"] is False
        assert report["protocol_confirmed"] is False
        assert report["score_impact"] == 0
        return report

    report = run(["sub.example.com", "VLESS.example.com."], 3)
    assert report["results"][1]["normalized_host"] == "vless.example.com"
    assert report["results"][1]["marks"][0]["sources"] == ["target"]
    run(["sub.example.com", "vpn.example.com"], 2)
    run(["vless.example.com"], 3, command="name")
    weak = run(["tor.example.com"], 0)
    assert weak["results"][0]["weak"] > 0
    assert run([], 64)["error"]
    invalid = run(["vless..example.com", "www.example.com"], 64)
    assert [r["status"] for r in invalid["results"]] == ["invalid", "hostname"]
    run(["vless.example.com", "https://sub.example.com/path"], 64)
    assert run(["203.0.113.189", "[2001:db8::1]"], 0)["results"][0]["status"] == "ip_literal"
    run(["notnordvpn.com", "us8360.nordvpn.com.example"], 0)
    assert run(["site.account.workers.dev"], 0)["results"][0]["marks"][0]["kind"] == "hosting_domain"
    assert any(m["kind"] == "provider_node" for m in run(["us8360.nordvpn.com"], 2)["results"][0]["marks"])
    assert run(["xn--b1awf.example.com"], 2)["results"][0]["marks"][0]["decoded_label"] == "впн"
    run(["xn--" + "z" * 58 + ".example"], 64)
    assert "no naming markers" in run(["www.example.com"], 0, False)
    assert "IP literal" in run(["203.0.113.189"], 0, False)
    assert "error:" in run(["vless..example.com"], 64, False)

    # names --ct from saved crt.sh answers, no network
    fixtures = Path(__file__).resolve().parent / "fixtures" / "ct"

    def ct(domain, path, code, as_json=True):
        result = subprocess.run([exe, "names", domain, "--ct-file", str(path), "--json" if as_json else "--no-color"],
                                capture_output=True, text=True, encoding="utf-8", timeout=10)
        assert result.returncode == code, (result.returncode, result.stdout, result.stderr)
        return json.loads(result.stdout) if as_json else result.stdout

    marked = ct("example.com", fixtures / "marked.json", 3)
    names = [n["name"] for n in marked["names"]]
    assert marked["lookup_complete"] and marked["certificates"] == 4, marked
    assert names[0] == "remnawave.example.com" and "panel.example.com" in names, names
    assert "admin@example.com" not in names and "example.com.evil.net" not in names, names
    plain = ct("example.org", fixtures / "plain.json", 0)
    assert all(not n["marks"] for n in plain["names"]), plain
    assert ct("example.com", fixtures / "missing.json", 4)["lookup_complete"] is False
    ct("203.0.113.5", fixtures / "marked.json", 64)
    text = ct("example.com", fixtures / "marked.json", 3, False)
    assert "CT logs are public" in text and "remnawave.example.com" in text, text
    print("names CLI regressions passed")


if __name__ == "__main__":
    main()
