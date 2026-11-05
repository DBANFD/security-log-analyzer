# Validation

## Version 0.3.0 update, 2026-11-05

- 70 tests passed on Windows Python 3.11, 3.13, and 3.14, including the existing native EVTX/ETL fixture tests.
- Added 33 tests for CEF escaped pipes/backslashes/equals/newlines, space-containing values, duplicate/malformed input warnings, provider-specific numeric IDs, LEEF 1.0 tabs and 2.0 literal/hex delimiters, supported/unsupported device times, W3C changing headers/UTC/missing fields/quoted values, and nested JSON arrays/objects/wrappers/pointers/mappings.
- JSON tests cover chunk boundaries, original-object preservation, ambiguous arrays/leaves, unsupported path syntax, duplicate keys, nonstandard numeric constants, oversized/deep input, partial-batch cancellation, and whole-file rollback on late syntax errors.
- Four new synthetic sample files imported nine events with zero rejected, undated, or warning events. Correlation at the explicitly lowered demo threshold of three identified three failure events across CEF/LEEF/JSON source files; the W3C HTTP 401 was excluded.
- CLI custom JSON Pointer selection imported the expected two events. The updated GUI was checked for parser/path controls, source quality labels, and event display.
- The standalone nested JSON benchmark imported 100,000 events from a 19.6 MiB input into an 85.0 MiB case in 17.83 seconds, at 47.1 MiB peak process working set. Run `py -3 tools/benchmark_json.py --folder work/json-benchmark-new` to reproduce with a fresh folder. Measurements are specific to this machine and short synthetic records; they are not multi-gigabyte/vendor coverage guarantees.
- No external runtime packages were added. Hosted GitHub Actions and real vendor exports remain unverified. The release ZIP is checked separately after extraction.

## Version 0.2.0 update, 2026-11-05

- 37 tests passed on Windows Python 3.11, 3.13, and 3.14, with native fixture tests enabled.
- Native fixtures were generated using a private in-process ETW session for a synthetic provider, without elevation or changes to existing channels/sessions. Each ETL/EVTX fixture contains six synthetic payload events and two trace-header events. These binaries remain under ignored `work/` because trace headers can contain local machine metadata.
- Both native files imported eight events with zero rejected/undated records. Missing message resources and best-effort ETL conversion are explicitly counted as decode warnings. Synthetic message text remained searchable, and matching payload events had identical UTC timestamps in both formats.
- Native tests cover literal filenames with spaces, brackets, quotes, shell metacharacters and Unicode; cancellation after the first decoded event; child-process cleanup; and invalid-file rollback.
- XML tests cover Security/Sysmon fields, provider-scoped authentication failure detection, payload/System metadata isolation, UTF-16/gzip, malformed XML rollback, DTD/entity refusal, nested UserData, exact filters, and exported metadata/warnings.
- Schema-1 migration is additive, transactional, and repeatable; the test verifies preservation of existing rows. New metadata remains blank for old imports.
- The desktop was opened with a 214-event synthetic case. Event-ID/provider controls and source quality counters were visually reviewed.
- An initial system-wide test-trace attempt was denied by Windows. The final fixture generator uses a supported private in-process trace and does not elevate. An initial XML conversion test exposed a one-minute timezone-offset discrepancy; the shipped ETL path converts to EVTX and reads native UTC timestamps instead.
- No real customer logs, downloaded binary fixtures, or provider-specific production ETL files were used. Hosted CI and non-Windows desktop behavior remain unverified. The earlier CSV benchmark below is historical v0.1 evidence, not an EVTX/ETL performance claim.

To reproduce native checks on Windows:

```powershell
./tools/generate_windows_demo.ps1 -OutputDirectory work/native-test
$env:SLA_NATIVE_FIXTURES = (Resolve-Path work/native-test).Path
py -3 -m unittest discover -s tests -v
```

The ordinary test command skips the three native-fixture tests unless `SLA_NATIVE_FIXTURES` is set. Invalid-native-file tests run on Windows without fixtures. The CI workflow generates private synthetic fixtures on Windows, then runs the native suite.

## Version 0.1.0 baseline

Checked on Windows on 2026-11-05. All test data was synthetic. No tenant or customer exports were used.

## Automated checks

- 18 tests passed on Python 3.11, 3.13, and 3.14.
- Coverage includes CSV multiline parsing, Sentinel/Defender aliases, Syslog with/without an assigned year, key-value firewall logs, JSONL rejection, UTF-8 failure rollback, gzip, timestamp normalization, source deduplication, mid-import cancellation, fixed-window cross-source correlation, destination fan-out, IP/CIDR matching, pagination/filter injection, and safe report/CSV escaping.
- CLI demo imported 212 events from four files with zero rejected/undated records. One firewall timestamp used the explicit UTC assumption.
- Demo report with the local synthetic indicator list produced four findings: AUTH_BURST, DEST_FANOUT, and two LOCAL_IOC matches.
- Database connections are explicitly closed, including on errors and cancellation. This was verified through Windows temporary-case cleanup in tests.

## Synthetic scale benchmark

Command: `py -3.13 tools/benchmark.py`.

| Measurement | Result |
| --- | ---: |
| Python | 3.13.5, 64-bit Windows |
| Events | 1,000,000 |
| CSV size | 108.2 MiB |
| SQLite case size | 554.8 MiB |
| Fingerprint and import | 36.50 seconds |
| Analysis and summary | 7.01 seconds |
| Peak process working set | 56.4 MiB |
| Rejected records | 0 |

These are one-machine observations, not performance guarantees. The fixture has short records and low host/IP cardinality. Large raw messages, very high cardinality, long indicator lists, slow disks, and compressed inputs can behave differently. Multi-gigabyte files and concurrent use of a case were not validated. The benchmark records results under `work/benchmark/result.json`; generated inputs and cases are excluded from Git and distribution.

## Desktop and remaining checks

The native desktop was opened with the demo case. Overview totals, findings, and the finding-to-event pivot were checked visually. Worker-thread completion and evidence display were exercised. The status/footer layout was adjusted during visual review.

Local automated tests passed on three Python versions. GitHub Actions runs the Windows/Linux Python matrix; current results are available on the repository Actions page. Linux/macOS desktop behavior remains unvalidated. Vendor-specific schema variants require representative synthetic fixtures before support can be claimed. Version 0.3.0 provides an unsigned portable Windows x64 bundle in addition to Python source. No installer or signed executable is included. The frozen CLI was checked with CEF, LEEF, W3C, nested JSON, EVTX, and ETL synthetic fixtures.
