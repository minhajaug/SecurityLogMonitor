"""Synthetic JSONL events for the five agreed rules. No live system access."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path
import random
import time
from uuid import uuid4
from src.detection_rules import parse_timestamp

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_FILE = PROJECT_ROOT / "data" / "security_log.jsonl"
USERS = ["alice", "ben", "chloe", "daniel", "fatima", "minhaj"]
HOSTS = ["workstation-01", "workstation-02", "server-01", "server-02"]
SOURCE_IPS = ["10.0.0.15", "10.0.0.22", "10.0.0.31", "172.16.4.20"]


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def normal_event():
    username = random.choice(USERS)
    role = "admin" if username == "fatima" and random.random() < 0.1 else "user"
    return dict(timestamp=utc_now(), event_type="login", username=username,
                role=role, source_ip=random.choice(SOURCE_IPS), host=random.choice(HOSTS),
                status="success", message="User logged in successfully")


def brute_force_events(count):
    records = []
    for index in range(count):
        record = normal_event()
        record.update(username="alice", role="user", source_ip="203.0.113.50", host="workstation-01",
                      status="success" if index == count - 1 else "failed",
                      message="Synthetic authentication sequence")
        records.append(record)
    return records


def demo_events(count):
    records = [normal_event() for _ in range(5)] + brute_force_events(7)
    records.extend([privileged_login_event(), account_change_event(), malware_alert_event()])
    while len(records) < count:
        records.append(normal_event())
    return records[:count]


def privileged_login_event():
    return dict(timestamp=utc_now(), event_type="login", username="fatima", role="admin",
                source_ip="10.0.0.22", host="server-01", status="success", message="Administrator logged in")


def account_change_event():
    return dict(timestamp=utc_now(), event_type="account_change", username="new-admin", role="admin",
                source_ip="10.0.0.31", host="server-02", action="grant_admin", status="success",
                message="Administrative privileges granted to account")


def malware_alert_event():
    return dict(timestamp=utc_now(), event_type="malware_alert", username="chloe", role="user",
                source_ip="10.0.0.15", host="workstation-02", status="detected",
                malware_name="Synthetic.Test.File", message="Synthetic malware alert")


def generate_events(scenario, count):
    if count < 0:
        raise ValueError("count must be nonnegative")
    if scenario == "normal":
        return [normal_event() for _ in range(count)]
    if scenario == "brute_force":
        return brute_force_events(count)
    if scenario == "demo":
        return demo_events(count)
    raise ValueError("unknown scenario")


def append_json_line(path, record):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_LOG_FILE)
    parser.add_argument("--scenario", choices=["normal", "brute_force", "demo"], default="demo")
    parser.add_argument("--count", type=int, default=30)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--start-time", help="Optional timezone-aware synthetic start time, e.g. 2026-01-01T02:15:00Z")
    args = parser.parse_args()
    if args.count < 0:
        parser.error("--count must be nonnegative")
    if not math.isfinite(args.interval) or args.interval < 0:
        parser.error("--interval must be finite and nonnegative")
    try:
        start = parse_timestamp(args.start_time) if args.start_time else None
    except ValueError:
        parser.error("--start-time must be a valid timestamp with a timezone")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    print(f"Writing synthetic events to {args.output}")
    if start:
        print("Synthetic event clock enabled; emitted_at records the actual write time.")
    try:
        for index, record in enumerate(generate_events(args.scenario, args.count)):
            record["event_id"] = str(uuid4())
            record["emitted_at"] = utc_now()
            record["timestamp"] = (start + timedelta(seconds=index * args.interval)).isoformat() if start else record["emitted_at"]
            append_json_line(args.output, record)
            print(json.dumps(record))
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nLog generation stopped by user.")


if __name__ == "__main__":
    main()
