# SPDX-License-Identifier: GPL-3.0-or-later
"""scan every ground-truth stand and print the error matrix.

usage: python run.py <byebyevpn.exe> [--tag NAME] [--only A,C,H1] [--rescore] [--require-all]

per stand the scanner runs `scan <ip> --json --no-geoip --no-ct --ports ...`.
results land in .run/results/<tag>/ and a markdown matrix in matrix.md there.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict

import lab

# legacy builds print signal text only; map the stable prefixes to ids
LEGACY_SIGNAL_TEXT = [
    ("WireGuard-family response layout", "wg-family"),
    ("Prefixed WireGuard response layout", "wg-family"),
    ("SOCKS5 negotiation observed", "socks5"),
    ("SSTP-compatible setup response", "sstp"),
    ("GeoIP provider reports a Tor", "geo-tor"),
    ("providers report VPN usage", "geo-vpn"),
    ("providers report proxy usage", "geo-proxy"),
]
SCORED = ["wg-family", "wg-keyed", "socks5", "sstp"]
FLAG_LABELS = {"SUSPICIOUS", "OBVIOUSLY-VPN"}
# phrases that pin a product on the target; the blind-spot disclaimer is not one
REALITY_HINT = re.compile(r"Reality-hidden|Reality wrapper|Reality hidden-mode|XTLS ?/ ?Reality|"
                          r"HTTPS alt / Reality|confirm Xray, REALITY")
ACK_ALL_TEXT = re.compile(r"accept-hooks every TCP SYN|accepts every SYN|near-identical RTT")
QUIC_TEXT = re.compile(r"-> QUIC (Initial|Handshake|Retry|0-RTT|Version-Negotiation)|"
                       r"QUIC version-negotiation +RESP \d+B +QUIC ")


def fired_signals(rep):
    ids = set()
    for s in rep.get("signals", {}).get("scored", []) or []:
        ids.add(s.get("id"))
    for text in rep.get("signals", {}).get("major", []) or []:
        for prefix, sid in LEGACY_SIGNAL_TEXT:
            if prefix in text:
                ids.add(sid)
    return ids


def claims(name, text, rep):
    """printed statements about the target, each (claim, fired, truth).
    truth None means the stand gives no ground truth for it."""
    st = lab.STANDS[name]
    loop = st["ip"].startswith("127.")
    out = []
    # closed port on loopback always answers rst
    m = re.search(r"closed-port :\d+ behavior: (\S+)", text)
    if m and loop:
        out.append(("closed-port-drop", m.group(1) == "drop", False))
    # every loopback stand runs on this windows kernel
    m = re.search(r"OS guess:\S*\s+(.+)", text)
    if m and loop:
        g = m.group(1).lower()
        specific_wrong = any(k in g for k in ("linux", "bsd", "userspace", "tun", "go-runtime"))
        out.append(("os-guess-wrong", specific_wrong, False))
    reality = name in ("C", "D")
    out.append(("reality-hint", bool(REALITY_HINT.search(text)), reality))
    warp = bool(ACK_ALL_TEXT.search(text))
    # off-loopback truth depends on the scanning machine's own path
    ackall_truth = name == "I" or (not loop and ENV.get("path_ack_all", False))
    out.append(("ack-all-warning", warp, ackall_truth))
    silent = bool(re.search(r"silent-on-junk", text))
    # "silent on junk" is a statement of fact; true only where the service really drops junk
    out.append(("silent-on-junk-claim", silent, None))
    # json note or a printed classification line both claim quic
    notes = rep.get("signals", {}).get("notes", []) or []
    quic = any(n.get("tag") == "quic-endpoint" for n in notes) or bool(QUIC_TEXT.search(text))
    out.append(("quic-endpoint", quic, st.get("quic", False)))
    return out


def run_one(exe, name, outdir, timeout):
    st = lab.STANDS[name]
    ports = ",".join(str(p) for p in lab.SCAN_PORTS)
    cmd = [exe, "scan", st["ip"], "--json", "--no-geoip", "--no-ct", "--no-color", "--ports", ports]
    cmd += lab.keyed_args(st.get("keyed"))
    cmd += EXTRA
    t0 = time.monotonic()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, stdin=subprocess.DEVNULL)
        code, so, se = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired as e:
        code, so, se = -1, e.stdout or "", (e.stderr or "") + "\n[timeout]"
        so = so.decode() if isinstance(so, bytes) else so
        se = se.decode() if isinstance(se, bytes) else se
    dt = time.monotonic() - t0
    with open(os.path.join(outdir, name + ".json"), "w", encoding="utf-8") as f:
        f.write(so)
    with open(os.path.join(outdir, name + ".txt"), "w", encoding="utf-8") as f:
        f.write(se)
    with open(os.path.join(outdir, name + ".meta"), "w", encoding="utf-8") as f:
        json.dump({"exit": code, "secs": dt}, f)
    try:
        rep = json.loads(so)
    except ValueError:
        rep = {}
    return dict(name=name, code=code, secs=dt, rep=rep, text=se + so)


def matrix(results):
    cells = defaultdict(lambda: dict(TP=0, FP=0, TN=0, FN=0, INC=0))
    rows = []
    for r in results:
        st = lab.STANDS[r["name"]]
        rep = r["rep"]
        label = rep.get("label", "?")
        fired = fired_signals(rep)
        inc = {s.get("id") for s in rep.get("signals", {}).get("inconclusive", []) or []}
        for sid in SCORED:
            truth = sid in st["detectable"]
            c = cells[sid]
            if sid in inc and sid not in fired:
                c["INC"] += 1
            elif sid in fired:
                c["TP" if truth else "FP"] += 1
            else:
                c["FN" if truth else "TN"] += 1
        # the verdict itself: a flag on a clean stand is the costly error
        c = cells["verdict-flag"]
        flagged = label in FLAG_LABELS or rep.get("tspu", {}).get("a_hits", 0) > 0
        if label == "INCONCLUSIVE" or not label or label == "?":
            c["INC"] += 1
        elif flagged:
            c["TP" if st["vpn"] else "FP"] += 1
        else:
            c["FN" if st["vpn"] else "TN"] += 1
        for cl, fired_c, truth in claims(r["name"], r["text"], rep):
            c = cells[cl]
            if truth is None:
                c["INC"] += fired_c
                continue
            if fired_c:
                c["TP" if truth else "FP"] += 1
            else:
                c["FN" if truth else "TN"] += 1
        ok_labels = set(st["labels"])
        # through a local ack-all tunnel the honest answer is "unreliable"
        if not st["ip"].startswith("127.") and ENV.get("path_ack_all"):
            ok_labels |= {"UNRELIABLE"}
        rows.append((r["name"], st["ip"], label, rep.get("score"), rep.get("tspu", {}).get("tier", "?"),
                     ",".join(sorted(fired)) or "-", r["code"], r["secs"],
                     label in ok_labels))
    return cells, rows


def render(tag, exe, cells, rows, notes):
    out = ["# ground truth run `%s`" % tag, "",
           "exe: `%s`, %s" % (os.path.basename(exe), time.strftime("%Y-%m-%d %H:%M")), ""]
    for k, v in notes.items():
        out.append("- %s: %s" % (k, v))
    out += ["", "| stand | ip | label | score | tier | scored signals | exit | s | label ok |",
            "|---|---|---|---|---|---|---|---|---|"]
    for n, ip, label, score, tier, fired, code, secs, ok in rows:
        out.append("| %s | %s | %s | %s | %s | %s | %s | %.0f | %s |" % (
            n, ip, label, score, tier, fired, code, secs, "yes" if ok else "**no**"))
    out += ["", "| signal or claim | TP | FP | TN | FN | INC |", "|---|---|---|---|---|---|"]
    for k in sorted(cells):
        c = cells[k]
        out.append("| %s | %d | %s | %d | %d | %d |" % (
            k, c["TP"], ("**%d**" % c["FP"]) if c["FP"] else "0", c["TN"], c["FN"], c["INC"]))
    return "\n".join(out) + "\n"


# client-side runs: name, group that disables it, matrix row, address, dpi
# arguments ("@X" is the address of server X), expected label
CLIENT_CASES = [
    ("VZ", "VOLUME", "volume-freeze", "Z", ["--volume", "/big", "--control", "@V2/big"], "positive"),
    ("VV", "VOLUME", "volume-freeze", "V", ["--volume", "/big", "--control", "@V2/big"], "negative"),
    ("VY", "VOLUME", "volume-freeze", "Y", ["--volume", "/big", "--control", "@V2/big"], "negative"),
    ("VT", "VOLUME", "volume-freeze", "T", ["--volume", "/big", "--control", "@V2/big"], "inconclusive"),
    ("VA", "VOLUME", "volume-freeze", "A", ["--volume", "/", "--control", "@V2/big"], "not applicable"),
    ("VC", "VOLUME", "volume-freeze", "V", ["--volume", "/big", "--control", "@Z/big"], "inconclusive"),
    ("VN", "VOLUME", "volume-freeze", "V", ["--volume", "/big"], "inconclusive"),
    ("SM", "SNI", "sni-address", "N", ["--sni", lab.SNI_NAME, "--real", "@R"], "positive"),
    ("SP", "SNI", "sni-address", "A", ["--sni", lab.SNI_NAME, "--real", "@R"], "negative"),
    ("SB", "SNI", "sni-address", "N", ["--sni", lab.SNI_NAME, "--real", "@RB"], "inconclusive blocked"),
    ("SD", "SNI", "sni-address", "H1", ["--sni", lab.SNI_NAME, "--real", "@R"], "inconclusive"),
    ("SR", "SNI", "sni-address", "N", ["--sni", lab.SNI_NAME, "--real", "@H1"], "inconclusive"),
]


def client_ip(name):
    for table in (lab.VOLUME_SERVERS, lab.SNI_SERVERS, lab.STANDS):
        if name in table:
            return table[name]["ip"]
    raise KeyError(name)


def client_args(args):
    out = []
    for a in args:
        if a.startswith("@"):
            name, _, rest = a[1:].partition("/")
            a = client_ip(name) + ("/" + rest if rest else "")
        out.append(a)
    return out


def client_label(so):
    try:
        rep = json.loads(so)
    except ValueError:
        return "?"
    return rep.get("outcome", "?") + (" blocked" if rep.get("name_blocked") else "")


def run_client(exe, case, outdir, timeout):
    name, _, row, addr, args, expected = case
    ip = client_ip(addr)
    cmd = [exe, "dpi", ip, "443"] + client_args(args) + ["--json", "--no-color"]
    t0 = time.monotonic()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, stdin=subprocess.DEVNULL)
        code, so, se = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        code, so, se = -1, "", "[timeout]"
    dt = time.monotonic() - t0
    with open(os.path.join(outdir, name + ".json"), "w", encoding="utf-8") as f:
        f.write(so)
    with open(os.path.join(outdir, name + ".txt"), "w", encoding="utf-8") as f:
        f.write(se)
    return dict(name=name, ip=ip, row=row, outcome=client_label(so), expected=expected, code=code, secs=dt)


def client_matrix(vres, cells, rows):
    for v in vres:
        c = cells[v["row"]]
        fired, truth = v["outcome"] == "positive", v["expected"] == "positive"
        if v["outcome"] != "positive" and v["outcome"] != "negative":
            c["INC"] += 1
        elif fired:
            c["TP" if truth else "FP"] += 1
        else:
            c["FN" if truth else "TN"] += 1
        rows.append((v["name"], v["ip"], v["outcome"], None, "dpi " + v["row"], "-", v["code"], v["secs"],
                     v["outcome"] == v["expected"]))

def annotate(msg):
    # actions turns these into annotations, readable without a login
    if os.environ.get("GITHUB_ACTIONS"):
        print("::error title=groundtruth::" + msg.replace("%", "%25").replace("\r", "").replace("\n", "%0A"),
              flush=True)


def gate(cells, rows):
    bad = [row for row in rows if not row[-1]]
    # every row with a truth counts, printed claims included
    fp = [k for k, c in cells.items() if c["FP"]]
    for row in bad:
        annotate("%s %s: got %s, outside the accepted set" % (row[0], row[1], row[2]))
    for k in fp:
        annotate("false positive in row %s: %d" % (k, cells[k]["FP"]))
    return 1 if (bad or fp) else 0


EXTRA = []
ENV = {}


def probe_env():
    # rfc 5737 address never answers; a connect means a local ack-all stack
    import socket
    try:
        socket.create_connection(("192.0.2.1", 443), 2).close()
        ENV["path_ack_all"] = True
    except OSError:
        ENV["path_ack_all"] = False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("--tag", default=time.strftime("%Y%m%d-%H%M%S"))
    ap.add_argument("--only", default="")
    ap.add_argument("--timeout", type=int, default=420)
    ap.add_argument("--extra", default="", help="extra scanner args, space separated")
    ap.add_argument("--rescore", action="store_true", help="recompute matrix.md from saved results of --tag")
    ap.add_argument("--require-all", action="store_true", help="exit 1 when a stand could not start (ci)")
    a = ap.parse_args()
    exe = os.path.abspath(a.exe)
    EXTRA.extend(a.extra.split())
    names = [n for n in lab.STANDS if not a.only or n in a.only.split(",")]
    outdir = os.path.join(lab.RUN, "results", a.tag)
    os.makedirs(outdir, exist_ok=True)
    probe_env()
    if a.rescore:
        results = []
        for n in names:
            js, tx = os.path.join(outdir, n + ".json"), os.path.join(outdir, n + ".txt")
            if not os.path.isfile(js):
                continue
            so = open(js, encoding="utf-8").read()
            se = open(tx, encoding="utf-8").read()
            try:
                rep = json.loads(so)
            except ValueError:
                rep = {}
            meta = {"exit": "?", "secs": 0.0}
            mp = os.path.join(outdir, n + ".meta")
            if os.path.isfile(mp):
                meta = json.load(open(mp, encoding="utf-8"))
            results.append(dict(name=n, code=meta["exit"], secs=meta["secs"], rep=rep, text=se + so))
        vres = []
        for c in CLIENT_CASES:
            js = os.path.join(outdir, c[0] + ".json")
            if os.path.isfile(js) and (not a.only or c[0] in a.only.split(",")):
                vres.append(dict(name=c[0], ip=client_ip(c[3]), row=c[2], expected=c[5], code="?", secs=0.0,
                                 outcome=client_label(open(js, encoding="utf-8").read())))
        cells, rows = matrix(results)
        client_matrix(vres, cells, rows)
        md = render(a.tag + " (rescored)", exe, cells, rows, {"rescored": "same rules as a fresh run"})
        with open(os.path.join(outdir, "matrix.md"), "w", encoding="utf-8") as f:
            f.write(md)
        print(md)
        return gate(cells, rows)
    try:
        st, procs, notes = lab.start_all()
    except Exception:
        import traceback
        tb = traceback.format_exc()
        sys.stderr.write(tb)
        annotate("lab did not start: " + tb.strip().splitlines()[-1] + "\n" + tb[-1500:])
        return 1
    if "bind failed" in notes:
        annotate("listeners the host refused: " + notes["bind failed"])
    notes["path to 192.0.2.1"] = "ack-all (local tunnel answers every SYN)" if ENV["path_ack_all"] else "silent, as it should be"
    # a stand without its server would be judged as an empty address
    skipped = [n for n in names if n in lab.DISABLED]
    if skipped:
        notes["skipped"] = " ".join(skipped)
        names = [n for n in names if n not in lab.DISABLED]
    results, vres = [], []
    cases = [c for c in CLIENT_CASES if not a.only or c[0] in a.only.split(",")]
    off = [c for c in cases if c[1] in lab.DISABLED]
    if off:
        skipped += [c[0] for c in off]
        notes["skipped"] = " ".join(skipped)
        cases = [c for c in cases if c not in off]
    try:
        time.sleep(1)
        for n in names:
            lab.log("scanning %s (%s)" % (n, lab.STANDS[n]["ip"]))
            r = run_one(exe, n, outdir, a.timeout)
            lab.log("  %s label=%s score=%s exit=%s %.0fs" % (
                n, r["rep"].get("label"), r["rep"].get("score"), r["code"], r["secs"]))
            results.append(r)
        for c in cases:
            lab.log("client %s %s (%s)" % (c[0], c[2], client_ip(c[3])))
            v = run_client(exe, c, outdir, a.timeout)
            lab.log("  %s outcome=%s expected=%s exit=%s %.0fs" % (
                v["name"], v["outcome"], v["expected"], v["code"], v["secs"]))
            vres.append(v)
    finally:
        lab.stop_all(st, procs)
    cells, rows = matrix(results)
    client_matrix(vres, cells, rows)
    md = render(a.tag, exe, cells, rows, notes)
    with open(os.path.join(outdir, "matrix.md"), "w", encoding="utf-8") as f:
        f.write(md)
    print(md)
    if skipped and a.require_all:
        lab.log("stands not started: %s" % " ".join(skipped))
        annotate("stands not started: %s (%s)" % (" ".join(skipped), "; ".join(
            "%s: %s" % (k, v) for k, v in notes.items() if k in ("xray", "Q", "bind failed"))))
        return 1
    return gate(cells, rows)


if __name__ == "__main__":
    sys.exit(main())
