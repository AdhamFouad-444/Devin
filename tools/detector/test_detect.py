#!/usr/bin/env python3
"""Unit tests for detect.py classifiers — feed fabricated request/attack
records, assert the emitted incident kinds. Stdlib only.

Run: python tools/detector/test_detect.py  (or: python -m unittest)
"""

import json
import os
import tempfile
import unittest

import detect

T0 = 1_700_000_000.0
IP = "10.7.0.66"


def req(ip=IP, ts=T0, method="GET", path="/", query="", status=200, geo=None):
    return {
        "ts": ts, "ip": ip, "geo": geo,
        "method": method, "path": path, "query": query, "status": status,
    }


def attack(scenario, ip=IP, ts=T0, target="/login", result="ok"):
    return {
        "ts": ts, "scenario": scenario,
        "source": {"ip": ip, "geo": [37.62, 55.75, "Moscow (simulated)"]},
        "target_path": target, "result": result,
    }


class DetectorTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.det = detect.Detector(self.dir)

    def incidents(self):
        """open-status lines written to incidents.jsonl so far."""
        if not os.path.exists(self.det.incidents_path):
            return []
        with open(self.det.incidents_path) as f:
            return [
                json.loads(line)
                for line in f
                if json.loads(line)["status"] == "open"
            ]

    def kinds(self):
        return [r["kind"] for r in self.incidents()]

    # ---- requests.jsonl heuristics ----------------------------------------

    def test_sqli_marker_in_login_query(self):
        self.det.handle_request(req(
            method="POST", path="/login", status=200,
            query="user=%27%20OR%20%271%27%3D%271&pass=x",
        ))
        [inc] = self.incidents()
        self.assertEqual(inc["kind"], "sqli")
        self.assertEqual(inc["severity"], "high")
        self.assertEqual(inc["source_ip"], IP)
        self.assertTrue(inc["id"].startswith("INC-"))
        self.assertIn("' OR", inc["evidence"])

    def test_normal_login_is_not_sqli(self):
        self.det.handle_request(req(
            method="POST", path="/login", status=200,
            query="user=fatima&pass=s3cret-falcon",
        ))
        self.assertEqual(self.incidents(), [])

    def test_brute_force_threshold(self):
        for i in range(4):
            self.det.handle_request(req(
                ts=T0 + i, method="POST", path="/login", status=401,
                query="user=admin&pass=wrong",
            ))
        self.assertEqual(self.incidents(), [])  # 4 < threshold
        self.det.handle_request(req(
            ts=T0 + 4, method="POST", path="/login", status=401,
            query="user=admin&pass=wrong",
        ))
        [inc] = self.incidents()
        self.assertEqual(inc["kind"], "brute_force")
        self.assertEqual(inc["severity"], "med")

    def test_brute_force_window_expires(self):
        # 5 fails spread over 80s — the oldest falls out of the 60s window
        for i in range(5):
            self.det.handle_request(req(
                ts=T0 + i * 20, method="POST", path="/login", status=401,
                query="user=admin&pass=wrong",
            ))
        self.assertNotIn("brute_force", self.kinds())

    def test_scan_distinct_404s(self):
        for i in range(detect.SCAN_404_LIMIT - 1):
            self.det.handle_request(req(ts=T0 + i, path=f"/nope-{i}", status=404))
        self.assertEqual(self.incidents(), [])
        self.det.handle_request(req(ts=T0 + 9, path="/nope-9", status=404))
        [inc] = self.incidents()
        self.assertEqual(inc["kind"], "scan")
        self.assertEqual(inc["severity"], "med")

    def test_scan_same_path_repeated_does_not_count(self):
        for i in range(12):
            self.det.handle_request(req(ts=T0 + i, path="/missing", status=404))
        self.assertNotIn("scan", self.kinds())

    def test_scan_debug_config(self):
        self.det.handle_request(req(path="/debug/config", status=200))
        [inc] = self.incidents()
        self.assertEqual(inc["kind"], "scan")

    def test_dos_rate(self):
        for i in range(detect.DOS_LIMIT - 1):
            self.det.handle_request(req(ts=T0 + i * 0.3, path="/services"))
        self.assertEqual(self.incidents(), [])
        self.det.handle_request(req(ts=T0 + 24 * 0.3 + 0.1, path="/services"))
        [inc] = self.incidents()
        self.assertEqual(inc["kind"], "dos")
        self.assertEqual(inc["severity"], "high")

    def test_dos_below_rate_no_fire(self):
        # 24 requests spread over 24s — under the 10s window limit
        for i in range(24):
            self.det.handle_request(req(ts=T0 + i, path="/services"))
        self.assertNotIn("dos", self.kinds())

    def test_cve_probe_traversal(self):
        self.det.handle_request(req(path="/files", query="doc=../../etc/passwd", status=200))
        [inc] = self.incidents()
        self.assertEqual(inc["kind"], "cve_probe")
        self.assertEqual(inc["severity"], "med")

    def test_cve_probe_passwd_anywhere(self):
        self.det.handle_request(req(path="/files", query="doc=%2Fetc%2Fpasswd", status=200))
        [inc] = self.incidents()
        self.assertEqual(inc["kind"], "cve_probe")

    def test_normal_file_read_no_incident(self):
        self.det.handle_request(req(path="/files", query="doc=welcome.txt", status=200))
        self.assertEqual(self.incidents(), [])

    # ---- attacks.jsonl scenarios -------------------------------------------

    def test_attack_scenario_mapping(self):
        for i, (scenario, kind) in enumerate([
            ("sqli", "sqli"), ("brute", "brute_force"), ("scan", "scan"),
            ("dos", "dos"), ("cve", "cve_probe"),
        ]):
            self.det.handle_attack(attack(scenario, ip=f"10.9.0.{i}", ts=T0 + 100))
        self.assertEqual(
            self.kinds(),
            ["sqli", "brute_force", "scan", "dos", "cve_probe"],
        )

    def test_unknown_scenario_is_anomaly(self):
        self.det.handle_attack(attack("zero_day", ip="10.9.0.7"))
        [inc] = self.incidents()
        self.assertEqual(inc["kind"], "anomaly")

    # ---- emission contract ---------------------------------------------------

    def test_open_then_triaged_pair(self):
        self.det.handle_request(req(path="/debug/config"))
        with open(self.det.incidents_path) as f:
            rows = [json.loads(line) for line in f]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["status"], "open")
        self.assertEqual(rows[1]["status"], "triaged")
        self.assertEqual(rows[0]["id"], rows[1]["id"])
        self.assertEqual(rows[0]["kind"], rows[1]["kind"])

    def test_dedupe_within_60s(self):
        for i in range(3):
            self.det.handle_request(req(ts=T0 + i, path="/debug/config"))
        self.assertEqual(len(self.incidents()), 1)
        # fires again after the dedupe window
        self.det.handle_request(req(ts=T0 + 61, path="/debug/config"))
        self.assertEqual(len(self.incidents()), 2)

    def test_dedupe_per_ip(self):
        self.det.handle_request(req(ip="10.7.0.66", path="/debug/config"))
        self.det.handle_request(req(ip="10.7.0.99", path="/debug/config"))
        self.assertEqual(len(self.incidents()), 2)

    # ---- tailing robustness --------------------------------------------------

    def test_missing_and_partial_lines(self):
        self.det.poll_once()  # files don't exist yet — no crash
        with open(self.det.requests_path, "w") as f:
            f.write('{"ts": %d, "ip": "10.7.0.66", "method": "GET", "path": "/debug/con' % T0)
        self.det.poll_once()  # partial line held, nothing emitted
        self.assertEqual(self.incidents(), [])
        with open(self.det.requests_path, "a") as f:
            f.write('fig", "query": "", "status": 200}\n')
        self.det.poll_once()
        self.assertEqual(self.kinds(), ["scan"])

    def test_truncation_rereads(self):
        with open(self.det.requests_path, "w") as f:
            for i in range(3):  # long file -> large offset
                f.write(json.dumps(req(ts=T0 + i, path=f"/a-{i}", status=404)) + "\n")
        self.det.poll_once()
        with open(self.det.requests_path, "w") as f:  # truncate + rewrite shorter
            f.write(json.dumps(req(path="/debug/config")) + "\n")
        self.det.poll_once()
        self.assertIn("scan", self.kinds())


if __name__ == "__main__":
    unittest.main(verbosity=2)
