# Security Log Analyzer v0.3.0

Analyze security exports locally, correlate activity, and produce reports without uploading log contents to an external analysis service.

## Downloads

- **Security-Log-Analyzer-v0.3.0-windows-x64.zip**: portable Windows desktop and CLI. Python installation is not required. Extract the entire ZIP, then run `SecurityLogAnalyzer.exe`. Keep `_internal` beside the executables.
- **Security-Log-Analyzer-v0.3.0-source.zip**: source, documentation, tests, and synthetic samples. Requires Python 3.11 or later; Tk is needed for the desktop.
- **SHA256SUMS.txt**: hashes for the downloadable files.
- **Security-Log-Analyzer-demo-report.html**: a synthetic example report. Its authentication threshold is explicitly set to three for the small demo.

## Highlights

- Windows EVTX and best-effort ETL decoding, Windows Event XML, CEF/LEEF, IIS/W3C, nested JSON/JSONL, CSV/TSV, Syslog, and key-value logs.
- Streaming imports into SQLite, literal JSON Pointer selection, parser overrides, and full retained evidence.
- Event ID/provider/IP/time/text filters and local HTML/JSON/CSV exports.
- Cross-source authentication bursts, destination fan-out, and local IP/CIDR indicator matches.
- Explicit parse/decode warnings, rejected/undated counts, original source SHA-256 values, and per-file rollback/cancellation.

## Validation and limits

70 automated tests passed locally on Windows Python 3.11, 3.13, and 3.14, including EVTX/ETL fixtures. Synthetic benchmarks: one million short CSV events in 36.5 seconds at about 56 MiB peak working set (v0.1 baseline), and 100,000 nested JSON events in 17.83 seconds at 47.1 MiB (v0.3). These are machine-specific observations, not guarantees for arbitrary vendor exports.

Windows binaries are unsigned. Use your normal software-verification process; no security-policy bypass is required or recommended. Windows PowerShell and tracerpt must be available for native event imports. Cases/reports are plaintext local files. ETL provider completeness is not guaranteed. A finding is a triage lead, not proof of compromise. Public IP addresses alone are not suspicious. Read the included format and validation guides.
