# Requirements to Test Mapping

Updated: 12 October 2026. The user confirmed the earlier five-rule contract.
The generator and detector now match it. Evidence: `test-results-20261012-081107.md`
records 43 passing test methods on Python 3.15.0. This mapping covers the discussed
project scope; it is not a substitute for supervisor approval or the marking rubric.

## Confirmed Rules

| Rule | Behaviour | Severity |
|---|---|---|
| R1 | Five failed logins for one user within 60 seconds | Medium |
| R2 | Success following at least three failures for one user within 120 seconds | High |
| R3 | Successful login with admin, root or privileged role | Medium |
| R4 | Account change with create_admin, grant_admin or disable_security action | High |
| R5 | Malware-alert event | Critical |

Both time boundaries are inclusive. R4 flags the configured actions regardless
of status, and R5 flags the event type regardless of status. These are simple
indicator rules, not proof that the activity is malicious.

## Evidence Matrix

All PASS entries reference the report above and assertions in the named tests.

| ID | Requirement | Implementation | Test evidence | Result |
|---|---|---|---|---|
| FR01 | Generate the requested number of logs | `generate_events` | `test_exact_counts_all_scenarios`; `test_generator_cli_appends_and_timestamps` | PASS |
| FR02 | Support normal, brute-force and demo scenarios | `src/log_generator.py` | `test_demo_sequence`; `test_normal_events_are_successful_logins`; count tests | PASS |
| FR03 | Monitor new events from a file | `monitor_file` | `test_live_monitor_partial_invalid_and_repeated_demo` | PASS; historical records skipped at startup |
| FR04 | Detect R1 with threshold and time correlation | `SecurityRuleDetector` | `test_r1_below_threshold`; `test_r1_inclusive_60_second_boundary`; `test_r1_outside_window` | PASS |
| FR05 | Detect R2 with threshold and time correlation | `SecurityRuleDetector` | `test_r2_below_threshold`; `test_r2_inclusive_120_second_boundary`; `test_r2_outside_window` | PASS |
| FR06 | Detect privileged successful logins | R3 branch | `test_privileged_roles_and_severity`; `test_failed_admin_login_does_not_trigger_r3` | PASS |
| FR07 | Detect suspicious account changes | R4 branch | `test_account_actions`; `test_benign_account_change` | PASS |
| FR08 | Detect malware alerts | R5 branch | `test_malware_alert_creates_critical_incident` | PASS |
| FR09 | Supply severity, description and triage guidance | `_incident`, `print_incident` | Positive rule tests; `test_incident_schema_and_source_unchanged`; `test_alert_output_plain_and_coloured` | PASS |
| FR10 | Save incidents as JSON lines | `append_json_line` | `test_jsonl_append_preserves_records`; live test readback and unique IDs | PASS |
| FR11 | Skip invalid records without stopping monitoring | `parse_log_line` | `test_invalid_input_is_skipped`; live malformed-record recovery | PASS |
| FR12 | Preserve partially written records until newline | `monitor_file` | Live split-record test | PASS |
| FR13 | Avoid reusing old failures and suppress duplicates | Failure reset, burst state, event deduplication | `test_repeated_sequences_do_not_reuse_failed_logins`; `test_success_resets_subthreshold_failures`; `test_duplicate_event_returns_no_alert`; `test_r1_only_once_per_burst`; `test_r1_rearms_after_60_second_gap` | PASS |
| FR14 | Correlate users separately and interpret timezones | Timestamp parsing and per-user histories | `test_users_are_correlated_separately`; `test_timezone_equivalence`; `test_combined_r2_and_r3` | PASS |
| NFR01 | Run locally with no extra dependencies | Standard-library modules | CLI and live subprocess tests on Python 3.15; successful tests after copying to Documents | PASS for tested local environment |
| NFR02 | Provide readable symbols, colours and plain output | Terminal helpers | `test_alert_output_plain_and_coloured`; `test_narrow_terminal_wraps`; no-colour tests; screenshots S1 and S3-S5 | Automated PASS; native colours and readable context confirmed manually |
| NFR03 | Validate command parameters and stop handling | `main` functions | Invalid arguments; same-file rejection; directory creation; simulated KeyboardInterrupt | PASS; physical Ctrl+C check pending |
| NFR04 | Evaluate accuracy on controlled synthetic inputs | Evaluation fixtures | `test_controlled_1200_event_accuracy` | PASS: exactly 150 expected rule/event matches across 1,200 events; no extra or missing matches |
| NFR05 | Measure detection latency | Timestamped live incidents | Automated report at 0.01-second polling; ten saved manual-run alerts at default 0.5-second polling, detailed in `testing-and-evaluation.md` | PASS for observed samples: default mean 231.326 ms and maximum 279.736 ms; not a performance guarantee |
| SEC01 | Use synthetic data without collecting real system logs | Generator and project scope | Code inspection and synthetic fixtures | Supported by design; explain data handling in dissertation |

## Robustness Retained

Successful login closes the user's failure sequence only after R2 checks it.
R1 suppresses alerts within a burst and rearms when the recent count drops below
five. Duplicate events return no alerts; their cached history expires after 120
seconds. Generator events have unique IDs and actual emission timestamps.
Invalid and out-of-order records are skipped; incomplete lines wait for a newline.
Colours, source context, timestamps and triage output remain available.

## Remaining Evidence

1. Physical Ctrl+C evidence if required by the assessment.
2. Reconciliation with the approved proposal, ethics status and marking rubric.
3. Review and integrate `testing-and-evaluation.md` into the dissertation.

Generated browser views and capture helpers were removed at the user's request.
Eight original user-provided terminal screenshots are now retained in
`screenshots/`. The latest local report records 43 passing test methods. The
testing chapter maps all 43 methods and the manual cases to inputs, expected
results, actual results and comments. Default-polling delays were calculated
from the saved incidents for the two screenshot runs, using emission time rather
than simulated event time. The manual repeated runs were more than seven minutes
apart; rapid-repeat reset evidence comes from the automated regression test.

Synthetic accuracy is not real-world detection effectiveness. File rotation,
concurrent writers and prolonged memory/load behaviour remain untested. The
earlier alternate 600-second/multiple-account/out-of-hours contract is not active.
