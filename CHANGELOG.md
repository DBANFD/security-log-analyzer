# Changelog

## 0.3.0 - 2026-11-05

First GitHub release of Security Log Analyzer.

- Offline desktop and CLI with SQLite cases, source fingerprints, quality counters, filtering, and local reports.
- CSV/TSV, JSON/JSONL, Syslog, key-value logs, CEF/LEEF, IIS/W3C, Windows Event XML, EVTX, and ETL import.
- Streaming nested JSON arrays, common containers, and explicit JSON Pointer selection.
- Explainable authentication bursts, destination fan-out, and user-supplied IP/CIDR matching.
- Portable Windows x64 desktop and CLI executables, source ZIP, synthetic samples, and SHA-256 checksums.
- 70 automated tests, including native Windows fixtures. Synthetic CSV and nested-JSON scale measurements are documented.

Limitations: ETL decoding is best effort, binaries are unsigned, and vendor-specific schemas may need additional mappings. No cloud processing, telemetry, live log collection, or reputation lookup.
