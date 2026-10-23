from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

from src.detection_rules import SecurityRuleDetector, parse_timestamp


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_FILE = PROJECT_ROOT / "data" / "security_log.jsonl"
DEFAULT_INCIDENT_FILE = PROJECT_ROOT / "data" / "incidents.jsonl"
USE_COLOR = False


def enable_terminal_color() -> bool:
    if not sys.stdout.isatty() or "NO_COLOR" in os.environ:
        return False
    if os.name == "nt":
        # Enable ANSI colour sequences in Windows consoles.
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetStdHandle.restype = wintypes.HANDLE
        kernel.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        handle = kernel.GetStdHandle(-11)
        mode = wintypes.DWORD()
        if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel.SetConsoleMode(handle, mode.value | 0x0004))
    return True


def colour(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def print_field(label: str, value: str, width: int) -> None:
    print(textwrap.fill(f"{label}: {value}", width=width, subsequent_indent="  "))


def main() -> None:
    global USE_COLOR
    parser = argparse.ArgumentParser(description="Monitor synthetic logs and detect incidents.")
    parser.add_argument("--input", type=Path, default=DEFAULT_LOG_FILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_INCIDENT_FILE)
    parser.add_argument("--poll-interval", type=float, default=0.5)
    parser.add_argument("--no-color", action="store_true", help="Disable terminal colours.")
    args = parser.parse_args()
    if not math.isfinite(args.poll_interval) or args.poll_interval <= 0:
        parser.error("--poll-interval must be finite and greater than zero")
    if args.input.resolve() == args.output.resolve():
        parser.error("--input and --output must be different files")
    USE_COLOR = not args.no_color and enable_terminal_color()

    args.input.parent.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.input.touch(exist_ok=True)
    args.output.touch(exist_ok=True)

    detector = SecurityRuleDetector()

    print(colour("\nCOM7014 | SYNTHETIC SECURITY MONITOR", "1;36"))
    print(f"Log file: {args.input}")
    print(f"Incident file: {args.output}")
    print("Severity: " + colour("[!] MEDIUM", "33") + " | " + colour("[!!] HIGH", "31")
          + " | " + colour("[!!!] CRITICAL", "1;97;41"))

    try:
        monitor_file(args.input, args.output, detector, args.poll_interval)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")


def monitor_file(
    log_path: Path,
    incident_path: Path,
    detector: SecurityRuleDetector,
    poll_interval: float,
) -> None:
    with log_path.open("r", encoding="utf-8") as log_file:
        log_file.seek(0, 2)
        print(colour("[+] Waiting for new events. Press Ctrl+C to stop.\n", "32"), flush=True)
        last_event_time = None

        while True:
            position = log_file.tell()
            line = log_file.readline()

            if not line or not line.endswith("\n"):
                # A writer may not have finished the record yet.
                log_file.seek(position)
                time.sleep(poll_interval)
                continue

            event = parse_log_line(line)

            if event is None:
                continue

            event_time = parse_timestamp(event["timestamp"])
            if last_event_time is not None and event_time < last_event_time:
                print(colour("[!] Out-of-order event skipped.", "33"))
                continue
            last_event_time = event_time

            incidents = detector.check_event(event)

            for incident in incidents:
                if not incident:
                    continue

                append_json_line(incident_path, incident)
                print_incident(incident)


def parse_log_line(line: str) -> dict[str, Any] | None:
    try:
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError("record must be an object")
        required = ("timestamp", "event_type", "username", "role", "source_ip", "host", "status")
        if any(not isinstance(event.get(key), str) or not event[key].strip() for key in required):
            raise ValueError("required fields must be nonempty strings")
        if event["event_type"] == "privilege_change":
            for key in ("target_user", "new_role"):
                if not isinstance(event.get(key), str) or not event[key].strip():
                    raise ValueError("privilege changes need target_user and new_role")
        if "event_id" in event and (not isinstance(event["event_id"], str) or not event["event_id"]):
            raise ValueError("event_id must be a nonempty string")
        if event["event_type"] == "account_change" and (
            not isinstance(event.get("action"), str) or not event["action"].strip()
        ):
            raise ValueError("account changes need an action")
        if "emitted_at" in event:
            if not isinstance(event["emitted_at"], str):
                raise ValueError("emitted_at must be a timestamp string")
            parse_timestamp(event["emitted_at"])
        timestamp = parse_timestamp(event["timestamp"])
        if timestamp.utcoffset() is None:
            raise ValueError("timestamp needs a timezone")
        return event
    except (ValueError, TypeError):
        print(colour("[!] Invalid log record skipped.", "33"))
        return None


def append_json_line(path: Path, record: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as output_file:
        output_file.write(json.dumps(record) + "\n")


def print_incident(incident: dict[str, Any]) -> None:
    styles = {
        "Medium": ("[!]", "33"),
        "High": ("[!!]", "31"),
        "Critical": ("[!!!]", "1;97;41"),
    }
    severity = incident["severity"]
    symbol, code = styles.get(severity, ("[i]", "36"))
    width = max(20, min(88, shutil.get_terminal_size().columns - 1))
    event = incident.get("source_event", {})

    print(colour("-" * width, code))
    print(colour(f"{symbol} {severity.upper()} | {incident['rule_id']}", code))
    print(textwrap.fill(incident["rule_name"], width=width))
    print_field("Event time", event.get("timestamp", "Unknown"), width)
    print_field("Detected", incident.get("detected_at", "Unknown"), width)
    print_field("User", event.get("username", "Unknown"), width)
    print_field("Host", event.get("host", "Unknown"), width)
    print_field("Source IP", event.get("source_ip", "Unknown"), width)
    if "affected_accounts" in incident:
        print_field("Accounts", ", ".join(incident["affected_accounts"]), width)
    if "target_user" in event:
        print_field("Target account", event["target_user"], width)
    print()
    print_field("Details", incident["description"], width)
    print_field("> Action", incident["triage"], width)
    print(colour("-" * width, code))
    print()


if __name__ == "__main__":
    main()
