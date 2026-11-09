# Security Log Analyzer v0.4.0

Analyze security exports locally, correlate activity, and produce reports without uploading log contents to an external analysis service.

## Downloads

- **Security-Log-Analyzer-v0.4.0-windows-x64.zip**: portable Windows desktop and CLI. Python installation is not required. Extract the entire ZIP, then run `SecurityLogAnalyzer.exe`. Keep `_internal` beside the executables.
- **Security-Log-Analyzer-v0.4.0-source.zip**: source, documentation, tests, and synthetic samples. Requires Python 3.11 or later; Tk is needed for the desktop.
- **SHA256SUMS.txt**: hashes for the downloadable files.
- **Security-Log-Analyzer-demo-report.html**: a synthetic example report.

## New in 0.4.0

- Windows event rules per host: log cleared (1102/104), new service (7045/4697), member added to a security-enabled group (4728/4732/4756), account created (4720) and scheduled task created (4698). Event ID and exact provider must both match.
- Analyst tags and notes on individual events, a Notes tab, `note` CLI commands, and a notes section in reports.
- Per-source hourly timeline in the overview, reports and the new `timeline` command.
- Existing cases open and upgrade automatically; source events are never modified.

## Validation and limits

78 automated tests passed locally on Windows Python 3.14, plus an automated desktop check of findings, pivots and notes. GitHub Actions runs the Windows/Linux Python matrix.

Windows binaries are unsigned. Windows PowerShell and tracerpt must be available for native event imports. Cases/reports are plaintext local files. A finding is a triage lead, not proof of compromise. Windows rules flag activity to review; they do not judge whether a change was authorized. Notes are analyst opinions, not source evidence.
