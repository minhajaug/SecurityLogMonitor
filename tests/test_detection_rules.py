from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from src.detection_rules import SecurityRuleDetector


class DetectionRuleTests(unittest.TestCase):
    def test_repeated_sequences_do_not_reuse_failed_logins(self) -> None:
        detector = SecurityRuleDetector()
        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)

        def login(second: int, status: str, username: str = "alice") -> dict:
            return {
                "timestamp": (base_time + timedelta(seconds=second)).isoformat(),
                "event_type": "login",
                "username": username,
                "role": "user",
                "status": status,
            }

        for start in (0, 10, 20):
            incidents = []
            for index in range(6):
                incidents.extend(detector.check_event(login(start + index, "failed")))
            self.assertEqual([item["rule_id"] for item in incidents], ["R1"])
            self.assertIn("5 failed", incidents[0]["description"])

            self.assertEqual(detector.check_event(login(start + 6, "success", "ben")), [])
            success_incidents = detector.check_event(login(start + 7, "success"))
            self.assertEqual([item["rule_id"] for item in success_incidents], ["R2"])
            self.assertIn("6 recent failed", success_incidents[0]["description"])
            self.assertEqual(detector.check_event(login(start + 8, "success")), [])

    def test_multiple_failed_logins_create_medium_incident(self) -> None:
        detector = SecurityRuleDetector()
        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        incidents = []

        for index in range(5):
            incidents.extend(
                detector.check_event(
                    {
                        "timestamp": (base_time + timedelta(seconds=index)).isoformat(),
                        "event_type": "login",
                        "username": "alice",
                        "role": "user",
                        "source_ip": "203.0.113.50",
                        "host": "workstation-01",
                        "status": "failed",
                        "message": "Failed login attempt",
                    }
                )
            )

        self.assertEqual(incidents[-1]["rule_id"], "R1")
        self.assertEqual(incidents[-1]["severity"], "Medium")

    def test_failed_then_success_creates_high_incident(self) -> None:
        detector = SecurityRuleDetector()
        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)

        for index in range(3):
            detector.check_event(
                {
                    "timestamp": (base_time + timedelta(seconds=index)).isoformat(),
                    "event_type": "login",
                    "username": "alice",
                    "role": "user",
                    "source_ip": "203.0.113.50",
                    "host": "workstation-01",
                    "status": "failed",
                    "message": "Failed login attempt",
                }
            )

        incidents = detector.check_event(
            {
                "timestamp": (base_time + timedelta(seconds=4)).isoformat(),
                "event_type": "login",
                "username": "alice",
                "role": "user",
                "source_ip": "203.0.113.50",
                "host": "workstation-01",
                "status": "success",
                "message": "Successful login",
            }
        )

        self.assertEqual(incidents[0]["rule_id"], "R2")
        self.assertEqual(incidents[0]["severity"], "High")

    def test_privileged_login_creates_medium_incident(self) -> None:
        detector = SecurityRuleDetector()

        incidents = detector.check_event(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "login",
                "username": "fatima",
                "role": "admin",
                "source_ip": "10.0.0.22",
                "host": "server-01",
                "status": "success",
                "message": "Admin login",
            }
        )

        self.assertEqual(incidents[0]["rule_id"], "R3")

    def test_account_change_creates_high_incident(self) -> None:
        detector = SecurityRuleDetector()

        incidents = detector.check_event(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "account_change",
                "username": "new-admin",
                "role": "admin",
                "source_ip": "10.0.0.31",
                "host": "server-02",
                "action": "grant_admin",
                "status": "success",
                "message": "Admin privileges granted",
            }
        )

        self.assertEqual(incidents[0]["rule_id"], "R4")
        self.assertEqual(incidents[0]["severity"], "High")

    def test_malware_alert_creates_critical_incident(self) -> None:
        detector = SecurityRuleDetector()

        incidents = detector.check_event(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "malware_alert",
                "username": "chloe",
                "role": "user",
                "source_ip": "10.0.0.15",
                "host": "workstation-02",
                "status": "detected",
                "malware_name": "Synthetic.Test.File",
                "message": "Malware detected",
            }
        )

        self.assertEqual(incidents[0]["rule_id"], "R5")
        self.assertEqual(incidents[0]["severity"], "Critical")


if __name__ == "__main__":
    unittest.main()
