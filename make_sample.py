#!/usr/bin/env python3
"""Generate a synthetic authentication log with four hidden problems planted in it.

Nothing here comes from a real system. Run it, then run triage.py on the output and
check that the tool finds all four:
  1. one auth node with a secret mismatch (a NODE problem, many users affected)
  2. one user being push-bombed at 03:00 (PUSH-FATIGUE)
  3. one source address trying many users (SPRAY)
  4. one user fumbling their PIN (LOCKOUT-RISK) - the ordinary case
"""
import datetime as dt
import random

random.seed(7)
t0 = dt.datetime(2026, 3, 2, 8, 0, 0)
out = []


def ev(ts, node, user, src, method, result, reason=""):
    s = f"{ts:%Y-%m-%dT%H:%M:%SZ} {node} user={user} src={src} method={method} result={result}"
    out.append(s + (f" reason={reason}" if reason else ""))


users = [f"user{i:02d}" for i in range(1, 41)]
# background: mostly successful logins on three nodes
for i in range(400):
    ts = t0 + dt.timedelta(seconds=random.randint(0, 9 * 3600))
    ev(ts, random.choice(["auth-node-1", "auth-node-2", "auth-node-3"]), random.choice(users),
       f"10.1.{random.randint(1, 9)}.{random.randint(10, 200)}", "SecurID", "OK")
# 1. node 3 has a bad agent secret: everyone who lands there fails
for i in range(60):
    ts = t0 + dt.timedelta(minutes=30 + i * 3)
    ev(ts, "auth-node-3", random.choice(users), "10.1.5.20", "SecurID", "FAIL", "AGENT_SECRET_MISMATCH")
# 2. push fatigue against one user at 03:00 the next day
base = dt.datetime(2026, 3, 3, 3, 0, 0)
for i in range(9):
    ev(base + dt.timedelta(minutes=i), "auth-node-1", "user17", "203.0.113.50", "Push", "FAIL",
       "PUSH_DENIED" if i % 3 else "PUSH_TIMEOUT")
# 3. password spraying from one address
for i, u in enumerate(users[:12]):
    ev(t0 + dt.timedelta(hours=2, seconds=i * 20), "auth-node-2", u, "198.51.100.9", "Password", "FAIL",
       "LDAP_USER_NOT_FOUND")
# 4. an ordinary user mistyping a PIN
for i in range(6):
    ev(t0 + dt.timedelta(hours=5, seconds=i * 40), "auth-node-1", "user05", "10.1.2.31", "SecurID", "FAIL",
       "PASSCODE_INCORRECT")

out.sort()
open("sample.log", "w", encoding="utf-8").write("\n".join(out) + "\n")
print(f"wrote sample.log ({len(out)} events)")
