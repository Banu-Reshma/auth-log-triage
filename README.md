# auth-log-triage

Read an authentication log and say **why** logins failed, in one screen.

When logins break, the first question is never "which line failed" - it is *"is this one user,
one server, or one source address?"* The answer decides who you call and what you check first.
This tool answers that before you read a single log line.

```
$ python triage.py sample.log

events 487  success 400  failed 87

WHY (failures by reason)
     60  AGENT_SECRET_MISMATCH
         means: agent/node secret does not match the server
         check: re-push the node secret to the agent; this is a node problem, not a user problem
     ...
FLAGS
  [NODE] auth-node-3 fails 32% of its logins (60/187) vs 9% on its peers, across 33 users - look at the node/agent first, not the users
  [LOCKOUT-RISK] user05: 5+ failed attempts inside 10 min
  [PUSH-FATIGUE] user17: 9 unanswered/denied pushes - confirm with the user; treat as an attack until proven otherwise
  [SPRAY] 198.51.100.9 failed against 12 different users - possible password spraying
```

## What it flags

| Flag | Meaning | Why it matters |
|---|---|---|
| `NODE` | one server/agent fails far more often than its peers | the cause is configuration - stop interviewing users |
| `LOCKOUT-RISK` | a user burst of mistyped attempts | about to be locked; check before they open a ticket |
| `PUSH-FATIGUE` | many denied/unanswered pushes for one user | the classic MFA-bombing pattern |
| `SPRAY` | one source address failing against many users | password spraying |
| `SYSTEMIC` | one failure reason hitting many users | shared cause, not individual error |

Every failure reason also carries a one-line meaning and the *first thing to check*.

## Two design decisions worth knowing

**Node problems are found by failure *rate*, not share of failures.** My first version flagged a
node only if it held 70%+ of all failures. On the sample it held 69% and was missed - a busy,
healthy node produces many failures in absolute terms and hides the broken one. It now compares
each node's failure rate to its peers.

**Configuration failures are kept out of the user-attack flags.** A misconfigured agent host
looks exactly like "one source, many users", which is also what password spraying looks like. My
first version called the broken host an attacker. Config-class reasons are now excluded from the
spray and lockout counts. Both defects were found by running the tool on its own sample data, and
each has a regression test.

## Run it

```
python make_sample.py          # writes sample.log: 487 events with four problems planted in it
python triage.py sample.log    # human summary
python triage.py sample.log --json
python -m unittest             # 11 tests
```

Python 3.8+, standard library only. Options: `--lockout N` (burst size, default 5),
`--window SECONDS` (default 600).

## Log format

```
2026-03-02T09:14:07Z auth-node-1 user=jdoe src=10.1.4.22 method=SecurID result=FAIL reason=PASSCODE_INCORRECT
```

## Limits - read this

- **The data is synthetic.** `make_sample.py` generates it; no real system, customer or employer
  log was used or is included.
- **The log format is a simplified model**, not any vendor's native format. The failure reasons
  are modelled on common failure classes in token/MFA authentication. To use this on a real
  system you would write a small parser that maps its log lines into the format above.
- Thresholds (5 failures / 10 minutes, 3x peer failure rate) are sensible defaults, not tuned
  against production traffic.
- It reads files; it does not tail live logs or talk to any server.

## Why I built it

I work in authentication support. The expensive part of a ticket is rarely the fix - it is the
first twenty minutes working out *where* to look. This is that twenty minutes, automated.

MIT licensed.
