# Security Log Analyzer v0.5.0

Analyze security exports locally, correlate activity, and produce reports without uploading log contents to an external analysis service.

## Downloads

- **Security-Log-Analyzer-v0.5.0-windows-x64.zip**: portable Windows desktop and CLI. Python installation is not required. Extract the entire ZIP, then run `SecurityLogAnalyzer.exe`. Keep `_internal` beside the executables.
- **Security-Log-Analyzer-v0.5.0-source.zip**: source, documentation, tests, and synthetic samples. Requires Python 3.11 or later; Tk is needed for the desktop.
- **SHA256SUMS.txt**: hashes for the downloadable files.
- **Security-Log-Analyzer-demo-report.html**: a synthetic example report.

The two ZIP files carry a GitHub build provenance attestation: `gh attestation verify <zip> --repo DBANFD/security-log-analyzer`.

## New in 0.5.0

- Faster free-text search on large cases through a SQLite FTS5 trigram index. Matches are unchanged; the case file is larger and imports are slower in exchange.
- Authentication-burst and destination-fan-out rules use 5-minute sliding windows, so activity that straddles a clock boundary is found. Each source IP gets one finding for its busiest window.
- Add your own Windows event rules in `windows-rules.json` beside the application, or pass `--rules` to `report`. An example is in `samples/`.
- Existing cases open and upgrade automatically; the first open builds the search index. Source events are never modified. Earlier versions cannot open an upgraded case, so keep a backup.

## Validation and limits

91 automated tests passed locally on Linux with Python 3.13 (4 Windows-only tests skipped there). GitHub Actions runs the Windows/Linux Python matrix, including native EVTX and ETL fixtures on Windows. The desktop changes in this version (loading `windows-rules.json`) were not exercised by hand.

Findings from 0.4 and 0.5 can differ for the same case because the IP rules changed from fixed buckets to sliding windows. Windows binaries are unsigned. Windows PowerShell and tracerpt must be available for native event imports. Cases/reports are plaintext local files. A finding is a triage lead, not proof of compromise. Custom rules match event ID and provider only; they do not inspect event fields.
