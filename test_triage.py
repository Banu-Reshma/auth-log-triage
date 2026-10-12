import datetime as dt
import unittest

import triage


def line(ts, node, user, src, result, reason="", method="SecurID"):
    s = f"{ts:%Y-%m-%dT%H:%M:%SZ} {node} user={user} src={src} method={method} result={result}"
    return s + (f" reason={reason}" if reason else "")


T = dt.datetime(2026, 3, 2, 9, 0, 0)


class ParseTests(unittest.TestCase):
    def test_parses_good_lines_and_counts_bad_ones(self):
        ev, bad = triage.parse([line(T, "n1", "a", "1.1.1.1", "OK"), "garbage", "", "# comment"])
        self.assertEqual(len(ev), 1)
        self.assertEqual(bad, 1)

    def test_rejects_line_missing_result(self):
        ev, bad = triage.parse(["2026-03-02T09:00:00Z n1 user=a src=1.1.1.1"])
        self.assertEqual((len(ev), bad), (0, 1))


class AnalyseTests(unittest.TestCase):
    def kinds(self, lines):
        ev, _ = triage.parse(lines)
        return [k for k, _ in triage.analyse(ev)["findings"]]

    def test_node_problem_when_one_node_holds_most_failures(self):
        lines = [line(T + dt.timedelta(minutes=i), "n3", f"u{i}", "1.1.1.1", "FAIL", "AGENT_SECRET_MISMATCH")
                 for i in range(10)]
        lines += [line(T, "n1", "x", "1.1.1.1", "OK"), line(T, "n2", "y", "1.1.1.1", "OK")]
        self.assertIn("NODE", self.kinds(lines))

    def test_push_fatigue_detected(self):
        lines = [line(T + dt.timedelta(minutes=i), "n1", "victim", "9.9.9.9", "FAIL", "PUSH_DENIED", "Push")
                 for i in range(6)]
        self.assertIn("PUSH-FATIGUE", self.kinds(lines))

    def test_spray_needs_many_users_from_one_source(self):
        lines = [line(T + dt.timedelta(seconds=i), "n1", f"u{i}", "6.6.6.6", "FAIL", "LDAP_USER_NOT_FOUND")
                 for i in range(6)]
        self.assertIn("SPRAY", self.kinds(lines))

    def test_slow_failures_do_not_trip_lockout(self):
        lines = [line(T + dt.timedelta(hours=i), "n1", "slow", "1.1.1.1", "FAIL", "PASSCODE_INCORRECT")
                 for i in range(6)]
        self.assertNotIn("LOCKOUT-RISK", self.kinds(lines))

    def test_fast_failures_trip_lockout(self):
        lines = [line(T + dt.timedelta(seconds=i * 30), "n1", "fast", "1.1.1.1", "FAIL", "PASSCODE_INCORRECT")
                 for i in range(6)]
        self.assertIn("LOCKOUT-RISK", self.kinds(lines))

    # --- regressions found by running the tool on its own sample log ---
    def test_bad_node_found_by_rate_even_when_it_holds_under_70_percent_of_failures(self):
        lines = [line(T + dt.timedelta(minutes=i), "n3", f"u{i}", "10.0.0.9", "FAIL", "AGENT_SECRET_MISMATCH")
                 for i in range(12)]
        lines += [line(T + dt.timedelta(minutes=i), "n1", f"v{i}", "1.1.1.1", "OK") for i in range(40)]
        lines += [line(T + dt.timedelta(minutes=i), "n1", f"w{i}", "1.1.1.1", "FAIL", "PASSCODE_INCORRECT")
                  for i in range(8)]
        self.assertIn("NODE", self.kinds(lines))

    def test_broken_agent_host_is_not_called_password_spraying(self):
        lines = [line(T + dt.timedelta(seconds=i), "n3", f"u{i}", "10.0.0.9", "FAIL", "AGENT_SECRET_MISMATCH")
                 for i in range(12)]
        self.assertNotIn("SPRAY", self.kinds(lines))

    def test_push_bombing_is_not_also_reported_as_lockout(self):
        lines = [line(T + dt.timedelta(minutes=i), "n1", "victim", "9.9.9.9", "FAIL", "PUSH_DENIED", "Push")
                 for i in range(8)]
        kinds = self.kinds(lines)
        self.assertIn("PUSH-FATIGUE", kinds)
        self.assertNotIn("LOCKOUT-RISK", kinds)

    def test_clean_log_has_no_findings(self):
        self.assertEqual(self.kinds([line(T, "n1", "a", "1.1.1.1", "OK")]), [])


if __name__ == "__main__":
    unittest.main()
