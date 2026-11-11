# Changelog

## 0.5.0 - 2026-11-11

- Indexed free-text search: a SQLite FTS5 trigram index over host, user, action, message, provider and channel. Results are the same case-insensitive substring matches as before. Terms under three characters, and SQLite builds without the trigram tokenizer, fall back to the table scan. Expect a larger case file and a slower import in exchange (about 45 and 25 percent in a 300,000-event test).
- `AUTH_BURST` and `DEST_FANOUT` use 5-minute sliding windows instead of fixed UTC buckets, so a burst across a bucket edge is no longer missed. Each source IP now gets one finding, for its busiest window, where 0.4 listed one finding per bucket.
- Custom Windows event rules from JSON: `windows-rules.json` beside the application, or `report --rules path.json`. See `samples/windows-rules.example.json`.
- Case schema 4 adds the search index; 0.1 to 0.4 cases migrate automatically on open and are indexed once.
- Development: ruff and mypy run in CI, build tools are installed with `--require-hashes`, actions are pinned by commit, Dependabot watches pip and actions, and release archives carry a build provenance attestation.

## 0.4.0 - 2026-11-09

- Windows event rules per host: log cleared (1102/104), new service (7045/4697), member added to a security-enabled group (4728/4732/4756), account created (4720) and scheduled task created (4698). Event ID and exact provider must both match; `--no-windows-rules` disables them.
- Analyst tags and notes on events: evidence window entry, Notes tab, `note add/list/delete` CLI commands, and a notes section in HTML/JSON reports.
- Per-source hourly timeline in the overview, reports and new `timeline` command.
- Double-clicking a Windows finding filters events by its event ID and host.
- Case schema 3 adds the notes table; 0.1 to 0.3 cases migrate automatically on open.

## 0.3.0 - 2026-11-05

First GitHub release of Security Log Analyzer.

- Offline desktop and CLI with SQLite cases, source fingerprints, quality counters, filtering, and local reports.
- CSV/TSV, JSON/JSONL, Syslog, key-value logs, CEF/LEEF, IIS/W3C, Windows Event XML, EVTX, and ETL import.
- Streaming nested JSON arrays, common containers, and explicit JSON Pointer selection.
- Explainable authentication bursts, destination fan-out, and user-supplied IP/CIDR matching.
- Portable Windows x64 desktop and CLI executables, source ZIP, synthetic samples, and SHA-256 checksums.
- 70 automated tests, including native Windows fixtures. Synthetic CSV and nested-JSON scale measurements are documented.

Limitations: ETL decoding is best effort, binaries are unsigned, and vendor-specific schemas may need additional mappings. No cloud processing, telemetry, live log collection, or reputation lookup.
