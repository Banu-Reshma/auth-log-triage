#!/usr/bin/env python3
"""auth-log-triage - read an authentication log and say *why* logins failed.

Support engineers lose time reading thousands of lines to answer three questions:
is it ONE user, ONE server/agent, or ONE source address? This answers that first,
then maps each failure reason to the first thing to check.

Input is a plain log, one event per line:
    2026-03-02T09:14:07Z auth-node-1 user=jdoe src=10.1.4.22 method=SecurID result=FAIL reason=PASSCODE_INCORRECT
Standard library only. Python 3.8+.
"""

import argparse
import collections
import datetime as dt
import json
import re
import sys

LINE = re.compile(r"^(?P<ts>\S+)\s+(?P<node>\S+)\s+(?P<kv>.*)$")
KV = re.compile(r"(\w+)=(\S+)")

# reason -> (what it usually means, first thing to check)
HINTS = {
    "PASSCODE_INCORRECT": ("wrong PIN or tokencode typed", "ask user to wait for the next tokencode; check PIN-reset history"),
    "TIME_DRIFT": ("token clock and server clock disagree", "resync the token; check NTP on the auth server"),
    "TOKEN_DISABLED": ("token administratively disabled or expired", "check token status and expiry in the admin console"),
    "USER_LOCKED": ("account locked after repeated failures", "look for the failures that caused it; unlock only after confirming it is the user"),
    "NEXT_TOKENCODE_REQUIRED": ("server wants a second consecutive tokencode", "user must enter the next code; resync if it loops"),
    "AGENT_SECRET_MISMATCH": ("agent/node secret does not match the server", "re-push the node secret to the agent; this is a node problem, not a user problem"),
    "LDAP_USER_NOT_FOUND": ("identity source cannot find the user", "check LDAP sync/search base and whether the account was renamed"),
    "PUSH_DENIED": ("user (or attacker) rejected the push", "ask the user whether they initiated it"),
    "PUSH_TIMEOUT": ("push was never answered", "check device connectivity and notification permission"),
}
PUSH = {"PUSH_DENIED", "PUSH_TIMEOUT"}
# Failures caused by server/agent configuration, not by the people logging in. They must never be
# counted as lockout risk or spraying - a broken agent host *looks* like one source hitting many users.
CONFIG = {"AGENT_SECRET_MISMATCH", "TIME_DRIFT"}


def parse(lines):
    events, bad = [], 0
    for raw in lines:
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        m = LINE.match(raw)
        if not m:
            bad += 1
            continue
        kv = dict(KV.findall(m.group("kv")))
        try:
            ts = dt.datetime.strptime(m.group("ts"), "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            bad += 1
            continue
        if "result" not in kv or "user" not in kv:
            bad += 1
            continue
        events.append({"ts": ts, "node": m.group("node"), "user": kv["user"],
                       "src": kv.get("src", "?"), "method": kv.get("method", "?"),
                       "result": kv["result"].upper(), "reason": kv.get("reason", "")})
    return events, bad


def burst(times, count, window):
    """True if `count` events fall inside any `window`-second span."""
    times = sorted(times)
    for i in range(len(times) - count + 1):
        if (times[i + count - 1] - times[i]).total_seconds() <= window:
            return True
    return False


def analyse(events, lock_n=5, window=600):
    fails = [e for e in events if e["result"] == "FAIL"]
    out = {"events": len(events), "failures": len(fails), "success": len(events) - len(fails)}
    out["by_reason"] = collections.Counter(e["reason"] or "UNSPECIFIED" for e in fails).most_common()
    out["by_node"] = collections.Counter(e["node"] for e in fails).most_common()
    out["top_users"] = collections.Counter(e["user"] for e in fails).most_common(5)

    findings = []
    # 1. a node that fails far more often than its peers -> configuration, not users.
    #    Compare failure RATE per node, not share of failures: a busy healthy node holds many
    #    failures in absolute terms and would otherwise hide the broken one.
    per_node = collections.defaultdict(lambda: [0, 0])          # node -> [events, failures]
    for e in events:
        per_node[e["node"]][0] += 1
        if e["result"] == "FAIL":
            per_node[e["node"]][1] += 1
    if len(per_node) > 1:
        rates = {n: f / t for n, (t, f) in per_node.items() if t}
        for node, (t, f) in sorted(per_node.items()):
            others = [r for n, r in rates.items() if n != node]
            peer = sum(others) / len(others) if others else 0
            if f >= 10 and rates[node] >= 0.3 and rates[node] >= 3 * max(peer, 0.01):
                users = len({e["user"] for e in fails if e["node"] == node})
                findings.append(("NODE", f"{node} fails {rates[node]:.0%} of its logins ({f}/{t}) vs {peer:.0%} on its peers, "
                                         f"across {users} users - look at the node/agent first, not the users"))
    # 2. same reason, many users -> systemic (config-class reasons are reported under NODE instead)
    flagged_nodes = {m.split()[0] for k, m in findings if k == "NODE"}
    for reason, n in out["by_reason"]:
        users = {e["user"] for e in fails if (e["reason"] or "UNSPECIFIED") == reason}
        nodes = {e["node"] for e in fails if (e["reason"] or "UNSPECIFIED") == reason}
        if reason in HINTS and len(users) >= 5 and reason not in PUSH and not (nodes <= flagged_nodes):
            findings.append(("SYSTEMIC", f"{reason} hit {len(users)} different users - likely shared cause: {HINTS[reason][0]}"))
    # 3. per-user bursts. Config-class and push failures are excluded from lockout counting:
    #    the user did not mistype anything, and push has its own flag.
    by_user = collections.defaultdict(list)
    for e in fails:
        by_user[e["user"]].append(e)
    for user, ev in sorted(by_user.items()):
        typed = [e["ts"] for e in ev if e["reason"] not in CONFIG and e["reason"] not in PUSH]
        if burst(typed, lock_n, window):
            findings.append(("LOCKOUT-RISK", f"{user}: {lock_n}+ failed attempts inside {window // 60} min"))
        pushes = [e["ts"] for e in ev if e["reason"] in PUSH]
        if burst(pushes, lock_n, window):
            findings.append(("PUSH-FATIGUE", f"{user}: {len(pushes)} unanswered/denied pushes - confirm with the user; "
                                             "treat as an attack until proven otherwise, consider number matching"))
    # 4. one source, many users -> spraying. Config-class failures excluded: a misconfigured
    #    agent host is also "one source, many users" and is not an attacker.
    by_src = collections.defaultdict(set)
    for e in fails:
        if e["reason"] not in CONFIG:
            by_src[e["src"]].add(e["user"])
    for src, users in sorted(by_src.items()):
        if len(users) >= 5:
            findings.append(("SPRAY", f"{src} failed against {len(users)} different users - possible password spraying"))
    out["findings"] = findings
    return out


def render(res, bad):
    o = []
    o.append(f"events {res['events']}  success {res['success']}  failed {res['failures']}"
             + (f"  unparsed {bad}" if bad else ""))
    if not res["failures"]:
        o.append("no failures in this log")
        return "\n".join(o)
    o.append("\nWHY (failures by reason)")
    for r, n in res["by_reason"]:
        hint = HINTS.get(r)
        o.append(f"  {n:5d}  {r}" + (f"\n         means: {hint[0]}\n         check: {hint[1]}" if hint else ""))
    o.append("\nWHERE (failures by node)")
    for n, c in res["by_node"]:
        o.append(f"  {c:5d}  {n}")
    o.append("\nWHO (top failing users)")
    for u, c in res["top_users"]:
        o.append(f"  {c:5d}  {u}")
    o.append("\nFLAGS")
    if res["findings"]:
        for kind, msg in res["findings"]:
            o.append(f"  [{kind}] {msg}")
    else:
        o.append("  none - failures look like ordinary user error")
    return "\n".join(o)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Summarise why authentications failed.")
    ap.add_argument("logfile", help="log file, or - for stdin")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--lockout", type=int, default=5, help="failures that count as a burst (default 5)")
    ap.add_argument("--window", type=int, default=600, help="burst window in seconds (default 600)")
    a = ap.parse_args(argv)
    src = sys.stdin if a.logfile == "-" else open(a.logfile, encoding="utf-8", errors="replace")
    events, bad = parse(src)
    res = analyse(events, a.lockout, a.window)
    if a.json:
        res["unparsed"] = bad
        print(json.dumps(res, indent=2, default=str))
    else:
        print(render(res, bad))
    return 0 if events else 2


if __name__ == "__main__":
    sys.exit(main())
