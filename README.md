# COM7014 Security Log Monitoring Proof of Concept

This is a simple Python proof-of-concept for synthetic security log monitoring.

The project generates fake security log events, monitors the log file in near real time, applies five detection rules, and records detected incidents for evaluation.

It is intentionally small and student-readable. It does not connect to real systems, servers, networks, firewalls, cloud services, or production logs.

## Project Scope

The proof-of-concept uses five detection rules only:

1. Multiple failed login attempts for the same user.
2. Failed login attempts followed by a successful login.
3. Privileged account login.
4. Suspicious account or privilege change.
5. Malware alert event.

## Folder Structure

```text
SecurityLogMonitor/
├── data/
│   ├── security_log.jsonl
│   └── incidents.jsonl
├── src/
│   ├── detection_rules.py
│   ├── log_generator.py
│   └── monitor.py
├── tests/
│   ├── test_detection_rules.py
│   ├── test_framework.py
│   └── run_report.py
├── README.md
└── requirements.txt
```

The `data` files are created automatically when you run the program.

## Requirements

- Python 3.10 or newer
- No extra Python packages are required

Check the installed runtime with `python --version`. The recorded tests used
Python 3.15.0 on Windows 11. Other supported versions have not all been tested.

## How to Run

Open a terminal in the project folder containing `src`, `tests` and this README.
When using the ZIP, extract it first and open the `SecurityLogMonitor` folder.

Start the monitor in the first terminal:

```powershell
python -m src.monitor
```

Open a second terminal in the same folder and run the log generator:

```powershell
python -m src.log_generator --scenario demo --count 40 --interval 0.2
```

The monitor will print incidents when a rule is triggered.

## Useful Commands

Generate successful logins (some privileged logins may trigger R3):

```powershell
python -m src.log_generator --scenario normal --count 20 --interval 0.2
```

Generate events likely to trigger failed-login rules:

```powershell
python -m src.log_generator --scenario brute_force --count 20 --interval 0.2
```

Generate events likely to trigger all rules:

```powershell
python -m src.log_generator --scenario demo --count 40 --interval 0.2
```

Run the tests:

```powershell
python -m unittest discover -s tests
```

Run all tests and save a dated evidence report (including live detection timing):

```powershell
python -m tests.run_report
```

Reports are saved in `reports/`. Tests use temporary log files. The suite covers
rule thresholds and time boundaries, negative cases, repeated sequences, all
generator scenarios, input validation, terminal formatting, storage, and separate
generator/monitor processes. The controlled evaluation checks 1,200 synthetic
events against 150 expected rule/event matches.

The monitor starts at the end of the file, so start it before the generator.
Records must be complete JSON lines with nonempty string fields: `timestamp`,
`event_type`, `username`, `role`, `source_ip`, `host`, and `status`. Account-change
records also require `action`. Timestamps must include a timezone and arrive in
chronological order. Invalid and out-of-order records are skipped with a warning.
Partial lines are held until the terminating newline arrives.

R1 uses five failures within 60 seconds, and R2 uses three failures within 120
seconds. Both include the exact boundary. A successful login closes the user's
failure sequence. A new below-threshold R1 window allows a later burst to alert.
R4 flags the configured account actions regardless of status; R5 flags any malware
alert event. The `normal` scenario may include admin logins and therefore R3 alerts.

Count must be a nonnegative integer; interval must be finite and nonnegative.
The demo reaches all five predefined scenarios at 15 logs. Higher counts add
random successful logins. Optional `--start-time` sets a timezone-aware synthetic
event clock; `emitted_at` still records the actual write time. When using that
option, use `emitted_at` rather than the simulated event timestamp for latency.
Generated records have unique event IDs. Duplicate IDs (or identical records
without IDs) are ignored while retained in the detector's 120-second cache.

The monitor polling interval must be finite and positive. Use `--no-color` on the
monitor to disable colours. Log rotation, concurrent writers and prolonged load
testing are outside the current test coverage.

## Project Documentation

- [Requirements-to-test mapping](reports/requirements-to-test-mapping.md)
- [Final workstation regression](reports/test-results-20261019-230515.md)

Personal academic documents, submission material, screenshots and generated log
files are intentionally excluded from this source repository. The application
does not provide encryption, backup, tamper-proof storage or automatic response.

## Output Files

Synthetic log events are saved here:

```text
data/security_log.jsonl
```

Detected incidents are saved here:

```text
data/incidents.jsonl
```

Each line is one JSON record. This makes the output easy to inspect and easy to use as evidence in the testing and evaluation section.
