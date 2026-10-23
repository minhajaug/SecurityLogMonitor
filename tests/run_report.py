"""Run the tests and save a dated Markdown evidence report."""
import io
import platform
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


class ReportResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rows = {}
        self.live_metrics = None

    def startTest(self, test):
        super().startTest(test)
        self.rows[test.id()] = "PASS"

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.rows[test.id()] = "FAIL"

    def addError(self, test, err):
        super().addError(test, err)
        self.rows[test.id()] = "ERROR"

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.rows[test.id()] = "SKIP"

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.rows[test.id()] = "FAIL"

    def stopTest(self, test):
        self.live_metrics = getattr(type(test), "live_metrics", None) or self.live_metrics
        super().stopTest(test)


def main():
    root = Path(__file__).resolve().parents[1]
    suite = unittest.defaultTestLoader.discover(str(root / "tests"))
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=ReportResult).run(suite)
    output = stream.getvalue()
    print(output)
    stamp = datetime.now(timezone.utc)
    report = ["# Framework Test Results", "", f"Run: {stamp.isoformat()}",
              f"Environment: Python {platform.python_version()} on {platform.platform()}",
              f"Result: {'PASS' if result.wasSuccessful() else 'FAIL'}; {result.testsRun} test methods.", "",
              "## Scope and Interpretation", "",
              "Inputs and exact expected results are the fixtures and assertions in tests/test_detection_rules.py and tests/test_framework.py. Parameterised methods also check several input variants. A PASS means every assertion in that method passed.", "",
              "The controlled accuracy test uses 1,200 events (30 demo sequences), with 150 expected rule/event matches. A pass requires exactly those 150 matches, with no missing or extra alerts. This is synthetic scenario accuracy, not a claim about real-world attack detection.", "",
              "The live test uses separate monitor and generator processes, temporary files, repeated scenarios, malformed records, a partially written record, and an out-of-order event. Historical records are skipped on startup. It checks every observed detection delay is below two seconds at a 0.01-second polling interval; this is a test target, not a production guarantee.", "",
              "## Results by Test", "", "| Test case | Actual result |", "|---|---|"]
    report.extend(f"| {name} | {status} |" for name, status in result.rows.items())
    if result.live_metrics:
        report.extend(["", "## Live Measurement", ""])
        report.extend(f"- {key}: {value}" for key, value in result.live_metrics.items())
    report.extend(["", "## Limits", "",
                   "Automated colour checks verify ANSI codes, symbols, plain output and wrapping. Actual colour appearance and physical Ctrl+C interaction need a manual terminal check. KeyboardInterrupt handling is tested through simulation. File rotation/truncation, concurrent generators, long-duration memory growth and real infrastructure are not covered. The monitor expects chronological, timezone-aware events and skips older arrivals. R4 flags configured actions regardless of status; R5 flags malware event types regardless of status. These are the current rule contracts.", "",
                   "## Full Test Output", "", "```text", output.rstrip(), "```", ""])
    directory = root / "reports"
    directory.mkdir(exist_ok=True)
    path = directory / f"test-results-{stamp.strftime('%Y%m%d-%H%M%S')}.md"
    path.write_text("\n".join(report), encoding="utf-8")
    print(f"Report saved: {path}")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
