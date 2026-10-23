"""Boundary, negative, CLI and live integration tests using temporary files."""
import contextlib
import io
import json
import os
import queue
import random
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from src import monitor
from src.detection_rules import SecurityRuleDetector
from src.log_generator import generate_events

ROOT = Path(__file__).resolve().parents[1]
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def event(second=0, **fields):
    record = dict(timestamp=(BASE + timedelta(seconds=second)).isoformat(),
                  event_type="login", username="alice", role="user",
                  source_ip="203.0.113.50", host="test-host", status="failed")
    record.update(fields)
    return record


class RuleBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.detector = SecurityRuleDetector()

    def feed(self, records):
        return [i for e in records for i in self.detector.check_event(e)]

    def test_r1_below_threshold(self):
        self.assertEqual(self.feed([event(i) for i in range(4)]), [])

    def test_r1_inclusive_60_second_boundary(self):
        alerts = self.feed([event(i) for i in (0, 10, 20, 30, 60)])
        self.assertEqual([i["rule_id"] for i in alerts], ["R1"])

    def test_r1_outside_window(self):
        self.assertEqual(self.feed([event(i) for i in (0, 10, 20, 30, 60.001)]), [])

    def test_r1_only_once_per_burst(self):
        self.assertEqual(len(self.feed([event(i) for i in range(20)])), 1)

    def test_r1_rearms_after_60_second_gap(self):
        alerts = self.feed([event(i) for i in (0, 1, 2, 3, 4, 70, 71, 72, 73, 74)])
        self.assertEqual([i["rule_id"] for i in alerts], ["R1", "R1"])

    def test_users_are_correlated_separately(self):
        self.assertEqual(self.feed([event(i, username=str(i % 2)) for i in range(8)]), [])

    def test_r2_below_threshold(self):
        self.assertEqual(self.feed([event(0), event(1), event(2, status="success")]), [])

    def test_r2_inclusive_120_second_boundary(self):
        alerts = self.feed([event(i) for i in (0, 1, 2)] + [event(120, status="success")])
        self.assertEqual([i["rule_id"] for i in alerts], ["R2"])

    def test_r2_outside_window(self):
        self.assertEqual(self.feed([event(i) for i in (0, 1, 2)] +
                                   [event(120.001, status="success")]), [])

    def test_success_resets_subthreshold_failures(self):
        self.assertEqual(self.feed([event(0), event(1), event(2, status="success"),
                                   event(3), event(4, status="success")]), [])

    def test_privileged_roles_and_severity(self):
        for role in ("admin", "root", "privileged"):
            with self.subTest(role=role):
                alerts = SecurityRuleDetector().check_event(event(role=role, status="success"))
                self.assertEqual([(i["rule_id"], i["severity"]) for i in alerts], [("R3", "Medium")])

    def test_failed_admin_login_does_not_trigger_r3(self):
        self.assertEqual(self.feed([event(role="admin")]), [])

    def test_account_actions(self):
        for action in ("create_admin", "grant_admin", "disable_security"):
            with self.subTest(action=action):
                alerts = SecurityRuleDetector().check_event(event(event_type="account_change", action=action))
                self.assertEqual([(i["rule_id"], i["severity"]) for i in alerts], [("R4", "High")])

    def test_benign_account_change(self):
        self.assertEqual(self.feed([event(event_type="account_change", action="change_display_name")]), [])

    def test_unknown_event_type(self):
        self.assertEqual(self.feed([event(event_type="heartbeat")]), [])

    def test_duplicate_event_returns_no_alert(self):
        record = event(event_type="malware_alert")
        self.assertEqual(len(self.detector.check_event(record)), 1)
        self.assertEqual(self.detector.check_event(record), [])

    def test_combined_r2_and_r3(self):
        alerts = self.feed([event(i) for i in range(3)] + [event(3, status="success", role="admin")])
        self.assertEqual([i["rule_id"] for i in alerts], ["R2", "R3"])

    def test_timezone_equivalence(self):
        records = [event(i) for i in range(3)]
        records.append(event(timestamp="2026-01-01T01:00:03+01:00", status="success"))
        self.assertEqual([i["rule_id"] for i in self.feed(records)], ["R2"])

    def test_incident_schema_and_source_unchanged(self):
        record = event(event_type="malware_alert")
        original = record.copy()
        alert = self.detector.check_event(record)[0]
        for key in ("incident_id", "detected_at", "rule_id", "rule_name", "severity", "description", "triage", "source_event"):
            self.assertTrue(alert[key])
        self.assertEqual(alert["source_event"], original)
        self.assertEqual(record, original)
        self.assertEqual(alert["severity"], "Critical")


class GeneratorTests(unittest.TestCase):
    def test_controlled_1200_event_accuracy(self):
        detector = SecurityRuleDetector()
        records = []
        expected = set()
        with patch("src.log_generator.random.choice", side_effect=lambda choices: choices[0]):
            for run in range(30):
                start = len(records)
                records.extend(generate_events("demo", 40))
                expected.update((start + offset, rule) for offset, rule in
                                ((9, "R1"), (11, "R2"), (12, "R3"), (13, "R4"), (14, "R5")))
        actual = []
        for index, record in enumerate(records):
            record["timestamp"] = (BASE + timedelta(seconds=index * 0.2)).isoformat()
            actual.extend((index, item["rule_id"]) for item in detector.check_event(record))
        self.assertEqual(len(actual), 150)
        self.assertEqual(set(actual), expected)

    def test_exact_counts_all_scenarios(self):
        for scenario in ("normal", "brute_force", "demo"):
            for count in (0, 1, 5, 15, 40, 100):
                with self.subTest(scenario=scenario, count=count):
                    self.assertEqual(len(generate_events(scenario, count)), count)

    def test_demo_sequence(self):
        records = generate_events("demo", 40)
        self.assertEqual([e["status"] for e in records[5:12]], ["failed"] * 6 + ["success"])
        self.assertEqual([e["event_type"] for e in records[12:15]], ["login", "account_change", "malware_alert"])
        self.assertTrue(all(e["status"] == "success" for e in records[15:]))

    def test_normal_events_are_successful_logins(self):
        self.assertTrue(all(e["event_type"] == "login" and e["status"] == "success"
                            for e in generate_events("normal", 100)))

    def test_deterministic_normal_user_control_has_no_alerts(self):
        with patch("src.log_generator.random.choice", side_effect=lambda choices: choices[0]):
            records = generate_events("normal", 100)
        detector = SecurityRuleDetector()
        self.assertEqual([i for e in records for i in detector.check_event(e)], [])

    def test_random_details_can_vary(self):
        state = random.getstate()
        try:
            random.seed(1)
            first = generate_events("normal", 20)
            random.seed(2)
            second = generate_events("normal", 20)
        finally:
            random.setstate(state)
        self.assertNotEqual([e["username"] for e in first], [e["username"] for e in second])


class MonitorTests(unittest.TestCase):
    def test_invalid_input_is_skipped(self):
        invalid = ["not json", "null", "[]", "42", '{}']
        for fields in ({"timestamp": "bad"}, {"timestamp": "2026-01-01T00:00:00"},
                       {"username": []}, {"event_type": None}, {"status": {}}, {"host": 3}):
            invalid.append(json.dumps(event(**fields)))
        with contextlib.redirect_stdout(io.StringIO()):
            for line in invalid:
                with self.subTest(line=line):
                    self.assertIsNone(monitor.parse_log_line(line))

    def test_valid_record_parses(self):
        self.assertEqual(monitor.parse_log_line(json.dumps(event())), event())

    def test_jsonl_append_preserves_records(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "incidents.jsonl"
            monitor.append_json_line(path, event(0))
            monitor.append_json_line(path, event(1))
            self.assertEqual([json.loads(line) for line in path.read_text().splitlines()], [event(0), event(1)])

    def test_alert_output_plain_and_coloured(self):
        for severity, symbol, code in (("Medium", "[!]", "33"), ("High", "[!!]", "31"), ("Critical", "[!!!]", "1;97;41")):
            alert = SecurityRuleDetector().check_event(event(event_type="malware_alert"))[0]
            alert["severity"] = severity
            for enabled in (False, True):
                with self.subTest(severity=severity, colour=enabled):
                    output = io.StringIO()
                    with patch.object(monitor, "USE_COLOR", enabled), contextlib.redirect_stdout(output):
                        monitor.print_incident(alert)
                    rendered = output.getvalue()
                    for label in (symbol, severity.upper(), "Event time:", "Detected:", "Source IP:", "> Action:"):
                        self.assertIn(label, rendered)
                    self.assertEqual("\033[" in rendered, enabled)
                    if enabled:
                        self.assertIn(f"\033[{code}m", rendered)

    def test_narrow_terminal_wraps(self):
        alert = SecurityRuleDetector().check_event(event(event_type="malware_alert"))[0]
        output = io.StringIO()
        with patch.object(monitor, "USE_COLOR", False), patch.object(monitor.shutil, "get_terminal_size", return_value=os.terminal_size((40, 20))), contextlib.redirect_stdout(output):
            monitor.print_incident(alert)
        self.assertTrue(all(len(line) <= 39 for line in output.getvalue().splitlines()))

    def test_no_colour_for_redirected_output(self):
        with patch.object(sys.stdout, "isatty", return_value=False):
            self.assertFalse(monitor.enable_terminal_color())

    def test_no_colour_environment(self):
        with patch.dict(os.environ, {"NO_COLOR": "1"}), patch.object(sys.stdout, "isatty", return_value=True):
            self.assertFalse(monitor.enable_terminal_color())


class CommandTests(unittest.TestCase):
    def test_monitor_rejects_same_input_and_output(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "same.jsonl"
            result = subprocess.run([sys.executable, "-m", "src.monitor", "--input", str(path), "--output", str(path)], cwd=ROOT, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(path.exists())

    def test_monitor_creates_files_and_handles_keyboard_interrupt(self):
        with tempfile.TemporaryDirectory() as folder:
            logs, incidents = Path(folder) / "in" / "logs.jsonl", Path(folder) / "out" / "incidents.jsonl"
            with patch.object(sys, "argv", ["monitor", "--input", str(logs), "--output", str(incidents), "--no-color"]), patch.object(monitor, "monitor_file", side_effect=KeyboardInterrupt), contextlib.redirect_stdout(io.StringIO()) as output:
                monitor.main()
            self.assertTrue(logs.exists())
            self.assertTrue(incidents.exists())
            self.assertIn("Monitoring stopped", output.getvalue())

    def test_invalid_arguments_rejected(self):
        cases = [("src.log_generator", "--count", "-1"),
                 ("src.log_generator", "--count", "1.5"),
                 ("src.log_generator", "--interval", "-1"),
                 ("src.log_generator", "--interval", "nan"),
                 ("src.log_generator", "--scenario", "unknown"),
                 ("src.monitor", "--poll-interval", "0"),
                 ("src.monitor", "--poll-interval", "inf")]
        for module, flag, value in cases:
            with self.subTest(module=module, flag=flag, value=value), tempfile.TemporaryDirectory() as folder:
                output = Path(folder) / "output.jsonl"
                extra = ["--input", str(Path(folder) / "input.jsonl")] if module == "src.monitor" else []
                result = subprocess.run([sys.executable, "-m", module, flag, value, "--output", str(output)] + extra,
                                        cwd=ROOT, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(output.exists())

    def test_generator_cli_appends_and_timestamps(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "nested" / "logs.jsonl"
            for _ in range(2):
                result = subprocess.run([sys.executable, "-m", "src.log_generator", "--count", "3", "--interval", "0", "--output", str(path)], cwd=ROOT, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(len(records), 6)
            times = [datetime.fromisoformat(e["timestamp"]) for e in records]
            self.assertEqual(times, sorted(times))
            self.assertTrue(all(t.tzinfo for t in times))

    def test_live_monitor_partial_invalid_and_repeated_demo(self):
        with tempfile.TemporaryDirectory() as folder:
            logs, incidents = Path(folder) / "logs.jsonl", Path(folder) / "incidents.jsonl"
            logs.write_text(json.dumps(event(event_type="malware_alert")) + "\n", encoding="utf-8")
            process = subprocess.Popen([sys.executable, "-u", "-m", "src.monitor", "--input", str(logs), "--output", str(incidents), "--poll-interval", "0.01", "--no-color"], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            messages = queue.Queue()
            reader = threading.Thread(target=lambda: [messages.put(line) for line in process.stdout], daemon=True)
            reader.start()
            try:
                deadline = time.monotonic() + 5
                while True:
                    line = messages.get(timeout=max(0.01, deadline - time.monotonic()))
                    if "Waiting for new events" in line:
                        break
                    self.assertLess(time.monotonic(), deadline)
                time.sleep(0.05)
                self.assertEqual(incidents.read_text(), "")
                partial = json.dumps(event(event_type="malware_alert", timestamp=datetime.now(timezone.utc).isoformat()))
                with logs.open("a", encoding="utf-8") as stream:
                    stream.write("bad json\nnull\n")
                    stream.write(partial[:30])
                time.sleep(0.05)
                with logs.open("a", encoding="utf-8") as stream:
                    stream.write(partial[30:] + "\n")
                    stream.write(json.dumps(event(event_type="malware_alert")) + "\n")
                for _ in range(2):
                    result = subprocess.run([sys.executable, "-m", "src.log_generator", "--count", "15", "--interval", "0.01", "--output", str(logs)], cwd=ROOT, capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                deadline = time.monotonic() + 5
                records = []
                while time.monotonic() < deadline:
                    lines = incidents.read_text().splitlines(keepends=True)
                    records = [json.loads(line) for line in lines if line.endswith("\n")]
                    if Counter(i["rule_id"] for i in records)["R5"] >= 3:
                        break
                    self.assertIsNone(process.poll(), "Monitor exited unexpectedly")
                    time.sleep(0.02)
                counts = Counter(i["rule_id"] for i in records)
                self.assertEqual({k: counts[k] for k in ("R1", "R2", "R4", "R5")}, {"R1": 2, "R2": 2, "R4": 2, "R5": 3})
                generated = [json.loads(line) for line in logs.read_text().splitlines() if line.startswith('{')]
                self.assertEqual(counts["R3"], sum(e.get("role") == "admin" and e["event_type"] == "login" for e in generated))
                delays = [(datetime.fromisoformat(i["detected_at"]) - datetime.fromisoformat(i["source_event"]["timestamp"])).total_seconds() for i in records]
                self.assertTrue(all(0 <= delay < 2 for delay in delays), delays)
                type(self).live_metrics = {"incident_count": len(records), "minimum_latency_seconds": min(delays),
                                          "mean_latency_seconds": sum(delays) / len(delays),
                                          "maximum_latency_seconds": max(delays), "poll_interval_seconds": 0.01}
                self.assertEqual(len({i["incident_id"] for i in records}), len(records))
            finally:
                process.terminate()
                process.wait(timeout=5)
                reader.join(timeout=2)
                process.stdout.close()
