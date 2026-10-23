"""The five agreed COM7014 rules; input events arrive chronologically."""
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

FAILED_LOGIN_WINDOW_SECONDS = 60
FAILED_THEN_SUCCESS_WINDOW_SECONDS = 120
FAILED_LOGIN_LIMIT = 5
FAILED_THEN_SUCCESS_LIMIT = 3
PRIVILEGED_ROLES = {"admin", "root", "privileged"}


def parse_timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset() is None:
        raise ValueError("timestamp needs a timezone")
    return parsed.astimezone(timezone.utc)


class SecurityRuleDetector:
    def __init__(self):
        self.failed_by_user = defaultdict(deque)
        self.alerted_users = set()
        self.seen_events = {}

    def check_event(self, event):
        now = parse_timestamp(event["timestamp"])
        self._expire(now)
        key = event.get("event_id") or json.dumps(event, sort_keys=True)
        if key in self.seen_events:
            return []
        self.seen_events[key] = now
        user = event["username"]
        kind, status = event["event_type"], event["status"]
        alerts = []
        if kind == "login" and status == "failed":
            self.failed_by_user[user].append(now)
            cutoff = now - timedelta(seconds=FAILED_LOGIN_WINDOW_SECONDS)
            count = sum(timestamp >= cutoff for timestamp in self.failed_by_user[user])
            if count >= FAILED_LOGIN_LIMIT and user not in self.alerted_users:
                self.alerted_users.add(user)
                alerts.append(self._incident("R1", "Multiple failed login attempts", "Medium", event,
                    f"{count} failed login attempts detected for user {user} within 60 seconds.",
                    "Check whether the account owner recognises the activity."))
        if kind == "login" and status == "success":
            count = len(self.failed_by_user.get(user, ()))
            if count >= FAILED_THEN_SUCCESS_LIMIT:
                alerts.append(self._incident("R2", "Failed logins followed by successful login", "High", event,
                    f"Successful login for {user} happened after {count} recent failed attempts.",
                    "Review the source IP address and confirm whether the login was legitimate."))
            # Check R2 before closing this user's failure sequence.
            self.failed_by_user.pop(user, None)
            self.alerted_users.discard(user)
        if kind == "login" and status == "success" and event["role"] in PRIVILEGED_ROLES:
            alerts.append(self._incident("R3", "Privileged account login", "Medium", event,
                f"Privileged login detected for user {user}.",
                "Confirm whether the privileged login was expected and authorised."))
        if kind == "account_change" and event.get("action") in {"create_admin", "grant_admin", "disable_security"}:
            alerts.append(self._incident("R4", "Suspicious account or privilege change", "High", event,
                f"Suspicious account change detected: {event['action']} for user {user}.",
                "Check who made the change and whether it was approved."))
        if kind == "malware_alert":
            alerts.append(self._incident("R5", "Malware alert event", "Critical", event,
                f"Malware alert detected on host {event['host']}.",
                "Isolate the affected host and review the malware alert details."))
        return alerts

    def _expire(self, now):
        cutoff = now - timedelta(seconds=FAILED_THEN_SUCCESS_WINDOW_SECONDS)
        burst_cutoff = now - timedelta(seconds=FAILED_LOGIN_WINDOW_SECONDS)
        for user in list(self.failed_by_user):
            records = self.failed_by_user[user]
            while records and records[0] < cutoff:
                records.popleft()
            if sum(timestamp >= burst_cutoff for timestamp in records) < FAILED_LOGIN_LIMIT:
                self.alerted_users.discard(user)
            if not records:
                del self.failed_by_user[user]
        self.seen_events = {key: timestamp for key, timestamp in self.seen_events.items() if timestamp >= cutoff}

    @staticmethod
    def _incident(rule, name, severity, event, description, triage):
        return dict(incident_id=str(uuid4()), detected_at=datetime.now(timezone.utc).isoformat(),
                    rule_id=rule, rule_name=name, severity=severity, description=description,
                    triage=triage, source_event=dict(event))
