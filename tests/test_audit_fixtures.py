# SPDX-License-Identifier: GPL-3.0-or-later
"""run audit-config over tests/fixtures/audit and check tests/fixtures/audit/expect.txt.

usage: python tests/test_audit_fixtures.py ./byebyevpn.exe
"""
import json
import os
import subprocess
import sys

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "audit")


def audit(exe, paths):
    r = subprocess.run([exe, "audit-config", *paths, "--json", "--no-color"], capture_output=True,
                       text=True, encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL, timeout=60)
    return json.loads(r.stdout)


def main():
    exe = os.path.abspath(sys.argv[1])
    fails = 0
    seen = set()
    for line in open(os.path.join(HERE, "expect.txt"), encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        name, *rules = line.split()
        # "server.json+client.json" runs the pair check
        parts = name.split("+")
        seen.update(parts)
        rep = audit(exe, [os.path.join(HERE, p) for p in parts])
        if not rep.get("ok"):
            print("FAIL %s: %s" % (name, rep.get("error")))
            fails += 1
            continue
        cats = {f["tag"]: f["category"] for f in rep.get("findings", [])}
        tier = rep.get("tspu_tier", "")
        # tier prefixes may contain spaces in the json, rules use the first word
        for rule in rules:
            ok = True
            if rule.startswith("+"):
                ok = rule[1:] in cats
            elif rule.startswith("-"):
                ok = rule[1:] not in cats
            elif rule.startswith("cat:"):
                tag, cat = rule[4:].split("=", 1)
                ok = cats.get(tag) == cat
            elif rule.startswith("tier="):
                ok = tier.startswith(rule[5:])
            if not ok:
                print("FAIL %s: %s (tags %s, tier %s)" % (name, rule, sorted(cats), tier))
                fails += 1
    # a fixture without expectations checks nothing
    for f in sorted(os.listdir(HERE)):
        if f.endswith(".json") and f not in seen:
            print("FAIL %s: no line in expect.txt" % f)
            fails += 1
    print("audit fixtures: %d files, %d failures" % (len(seen), fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
