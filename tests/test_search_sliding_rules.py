import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from security_log_analyzer import core
from security_log_analyzer.core import (create_case, validate_case, import_file, analyze, connect, query_events,
                                        has_search_index, load_rules, Cancelled)
from security_log_analyzer.reports import export_csv


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.case = self.root / "case.sqlite"

    def ingest(self, rows, name="events.jsonl", **kwargs):
        path = self.root / name
        path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
        return import_file(self.case, path, **kwargs)


ROWS = [
    {"TimeGenerated": "2026-01-01T10:00:00Z", "Computer": "WEB-01", "Message": "Failed password for admin", "SourceIP": "10.0.0.1"},
    {"TimeGenerated": "2026-01-01T10:01:00Z", "Computer": "db-02", "Message": "100% done with under_score and back\\slash", "SourceIP": "10.0.0.2"},
    {"TimeGenerated": "2026-01-01T10:02:00Z", "Computer": "app-03", "Message": 'quoted "value" here OR there', "SourceIP": "10.0.0.3"},
]
# Each term must give the same rows with and without the index.
TERMS = ["web", "WEB-01", "password", "ass", "100%", "under_score", "r_s", "back\\slash", '"value"', "OR", "here OR there",
         "-02", "*", "pp-", "db", "a", "zz", "NEAR", "admin AND", "host:web", "(", "Failed password for admin"]


class SearchIndexTests(Base):
    def results(self, **kwargs):
        return [row["id"] for row in query_events(self.case, **kwargs)]

    def test_index_matches_table_scan_for_every_term(self):
        if not core.fts5_trigram_available():
            self.skipTest("This SQLite build has no FTS5 trigram tokenizer.")
        create_case(self.case)
        self.ingest(ROWS)
        with connect(self.case) as db:
            self.assertTrue(has_search_index(db))
        indexed = {term: self.results(search=term) for term in TERMS}
        with connect(self.case) as db:
            db.execute("UPDATE metadata SET value='none' WHERE key='search_index'")
        for term in TERMS:
            self.assertEqual(indexed[term], self.results(search=term), term)
        self.assertEqual(indexed["web"], [1])
        self.assertEqual(indexed["zz"], [])
        self.assertEqual(indexed["a"], [1, 2, 3])  # Shorter than a trigram: scan path.

    def test_search_combines_with_other_filters_and_export(self):
        create_case(self.case)
        self.ingest(ROWS)
        self.assertEqual(self.results(search="0", ip="10.0.0.2"), [2])
        self.assertEqual(self.results(search="here", start="2026-01-01T10:02:00Z"), [3])
        out = self.root / "out.csv"
        self.assertEqual(export_csv(self.case, out, search="password"), 1)

    def test_cancelled_or_failed_import_leaves_no_index_rows(self):
        if not core.fts5_trigram_available():
            self.skipTest("This SQLite build has no FTS5 trigram tokenizer.")
        create_case(self.case)
        self.ingest(ROWS)
        class CancelLate:
            """Reports cancellation only on the last checks, after rows were inserted."""
            calls = 0

            def is_set(self):
                self.calls += 1
                return self.calls > 2

        with self.assertRaises(Cancelled):
            self.ingest([dict(r, Message="second batch uniqueterm") for r in ROWS], "more.jsonl", cancel=CancelLate())
        self.assertEqual(self.results(search="uniqueterm"), [])
        self.assertEqual(self.results(search="password"), [1])
        with connect(self.case) as db:
            db.execute("INSERT INTO events_fts(events_fts) VALUES('integrity-check')")
        self.ingest([dict(r, Message="third batch otherterm") for r in ROWS], "third.jsonl")
        self.assertEqual(len(self.results(search="otherterm")), 3)

    def test_schema_3_case_is_indexed_on_open(self):
        if not core.fts5_trigram_available():
            self.skipTest("This SQLite build has no FTS5 trigram tokenizer.")
        create_case(self.case)
        self.ingest(ROWS)
        with connect(self.case) as db:
            db.execute("DROP TABLE events_fts")
            db.execute("DELETE FROM metadata WHERE key='search_index'")
            db.execute("UPDATE metadata SET value='3' WHERE key='schema_version'")
        validate_case(self.case)
        with connect(self.case) as db:
            self.assertTrue(has_search_index(db))
            self.assertEqual(db.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()[0], "4")
        self.assertEqual(self.results(search="password"), [1])
        validate_case(self.case)  # Idempotent.

    def test_case_works_without_fts5(self):
        with mock.patch.object(core, "fts5_trigram_available", return_value=False):
            create_case(self.case)
            self.ingest(ROWS)
        with connect(self.case) as db:
            self.assertFalse(has_search_index(db))
            tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE name='events_fts'")]
        self.assertEqual(tables, [])
        self.assertEqual(self.results(search="password"), [1])
        self.ingest([dict(ROWS[0], Message="later import")], "later.jsonl")
        self.assertEqual(len(self.results(search="later")), 1)


class SlidingWindowTests(Base):
    def setUp(self):
        super().setUp()
        create_case(self.case)

    def failure(self, stamp, ip="203.0.113.5"):
        return {"TimeGenerated": stamp, "Message": "Failed password for root", "SourceIP": ip}

    def test_burst_across_a_fixed_bucket_edge_is_found(self):
        # 10:04:00 to 10:06:00 straddles the 10:05 boundary: three and three in fixed buckets.
        stamps = ["10:04:00", "10:04:30", "10:04:50", "10:05:10", "10:05:40", "10:06:00"]
        self.ingest([self.failure(f"2026-01-01T{s}Z") for s in stamps])
        findings = [f for f in analyze(self.case, failure_threshold=5) if f["rule"] == "AUTH_BURST"]
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual((finding["entity"], finding["metric"], finding["events"]), ("203.0.113.5", 6, 6))
        self.assertEqual((finding["first"], finding["last"]), ("2026-01-01T10:04:00.000+00:00", "2026-01-01T10:06:00.000+00:00"))
        self.assertEqual(finding["evidence_id"], 1)
        self.assertIn("sliding window", finding["reason"])

    def test_window_is_exactly_five_minutes_and_per_source(self):
        # Five failures spread over five minutes and one second: never five inside one window.
        spread = ["10:00:00", "10:01:15", "10:02:30", "10:03:45", "10:05:00"]
        rows = [self.failure(f"2026-01-01T{s}Z") for s in spread]
        # Another source with four in a window stays below the threshold of five.
        rows += [self.failure(f"2026-01-01T10:00:0{n}Z", "198.51.100.9") for n in range(4)]
        self.ingest(rows)
        self.assertEqual([f for f in analyze(self.case, failure_threshold=5) if f["rule"] == "AUTH_BURST"], [])
        # 299 seconds apart is inside the window.
        self.ingest([self.failure("2026-01-02T10:00:00Z", "192.0.2.7")] * 1 + [self.failure(f"2026-01-02T10:04:5{n}Z", "192.0.2.7") for n in range(4)] + [self.failure("2026-01-02T10:04:59Z", "192.0.2.7")], "second.jsonl")
        found = [f for f in analyze(self.case, failure_threshold=5) if f["rule"] == "AUTH_BURST"]
        self.assertEqual([(f["entity"], f["metric"]) for f in found], [("192.0.2.7", 6)])

    def test_one_finding_per_source_reports_the_peak_window(self):
        rows = [self.failure(f"2026-01-01T10:00:{n:02d}Z") for n in range(5)]
        rows += [self.failure(f"2026-01-01T12:00:{n:02d}Z") for n in range(9)]
        self.ingest(rows)
        found = [f for f in analyze(self.case, failure_threshold=5) if f["rule"] == "AUTH_BURST"]
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0]["metric"], found[0]["first"][:13]), (9, "2026-01-01T12"))

    def test_fanout_counts_distinct_destinations_in_the_window(self):
        rows = [{"TimeGenerated": f"2026-01-01T10:04:{30 + n:02d}Z", "SourceIP": "10.1.1.1", "DestinationIP": f"10.2.0.{n % 12}", "Message": "allow"} for n in range(30)]
        rows += [{"TimeGenerated": f"2026-01-01T10:05:{n:02d}Z", "SourceIP": "10.1.1.1", "DestinationIP": f"10.2.1.{n}", "Message": "allow"} for n in range(10)]
        self.ingest(rows)
        found = [f for f in analyze(self.case, fanout_threshold=20) if f["rule"] == "DEST_FANOUT"]
        self.assertEqual([(f["entity"], f["metric"], f["events"]) for f in found], [("10.1.1.1", 22, 40)])


class RuleFileTests(Base):
    SEC = "Microsoft-Windows-Security-Auditing"

    def write(self, data):
        path = self.root / "windows-rules.json"
        path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
        return path

    def test_custom_rule_matches_and_builtin_rules_still_run(self):
        create_case(self.case)
        self.ingest([
            {"TimeGenerated": "2026-01-01T10:00:00Z", "Computer": "dc1", "EventID": "4740", "Provider": self.SEC, "Message": "locked"},
            {"TimeGenerated": "2026-01-01T10:01:00Z", "Computer": "dc1", "EventID": "4740", "Provider": "Other", "Message": "not ours"},
            {"TimeGenerated": "2026-01-01T10:02:00Z", "Computer": "dc1", "EventID": "1102", "Provider": self.SEC, "Message": "cleared"},
        ])
        rules = load_rules(self.write([{"rule": "ACCOUNT_LOCKOUT", "event_ids": ["4740"], "providers": [self.SEC.upper()], "reason": "Account locked out."}]))
        found = {f["rule"]: f for f in analyze(self.case, custom_rules=rules)}
        self.assertEqual(found["ACCOUNT_LOCKOUT"]["events"], 1)
        self.assertEqual(found["ACCOUNT_LOCKOUT"]["reason"], "Account locked out.")
        self.assertIn("LOG_CLEARED", found)
        self.assertNotIn("ACCOUNT_LOCKOUT", {f["rule"] for f in analyze(self.case)})

    def test_invalid_rule_files_are_refused_with_the_rule_number(self):
        good = {"rule": "X_RULE", "event_ids": ["1"], "providers": ["p"], "reason": "r"}
        for bad in (
            "not json", "{}", [1], [dict(good, rule="lower")], [dict(good, rule="A'; DROP TABLE events;--")], [dict(good, rule="AUTH_BURST")],
            [dict(good, event_ids=[4740])], [dict(good, event_ids=["1 OR 1=1"])], [dict(good, event_ids=[])],
            [dict(good, providers=[])], [dict(good, providers=[""])], [dict(good, reason="")], [dict(good, reason="x" * 501)],
            [good] * 201,
        ):
            with self.assertRaises(ValueError, msg=str(bad)[:60]):
                load_rules(self.write(bad))
        with self.assertRaisesRegex(ValueError, "Rule 2"):
            load_rules(self.write([good, dict(good, rule="bad name")]))
        self.assertEqual(load_rules(self.write([])), [])
        with self.assertRaisesRegex(ValueError, "could not be read"):
            load_rules(self.root / "missing.json")

    def test_cli_report_takes_a_rule_file(self):
        create_case(self.case)
        self.ingest([{"TimeGenerated": "2026-01-01T10:00:00Z", "Computer": "dc1", "EventID": "4740", "Provider": self.SEC, "Message": "locked"}])
        rules = self.write([{"rule": "ACCOUNT_LOCKOUT", "event_ids": ["4740"], "providers": [self.SEC], "reason": "Account locked out."}])
        out = self.root / "report.json"
        run = subprocess.run([sys.executable, "-m", "security_log_analyzer", "report", str(self.case), str(out), "--rules", str(rules)], capture_output=True, text=True, cwd=Path(__file__).resolve().parent.parent)
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(out.read_text(encoding="utf-8"))
        self.assertIn("ACCOUNT_LOCKOUT", json.dumps(report))
        bad = self.write([{"rule": "bad"}])
        run = subprocess.run([sys.executable, "-m", "security_log_analyzer", "report", str(self.case), str(self.root / "r2.json"), "--rules", str(bad)], capture_output=True, text=True, cwd=Path(__file__).resolve().parent.parent)
        self.assertEqual(run.returncode, 1)
        self.assertIn("Rule 1", run.stderr)

    def test_bundled_example_is_valid(self):
        example = Path(__file__).resolve().parent.parent / "samples" / "windows-rules.example.json"
        self.assertGreaterEqual(len(load_rules(example)), 2)


if __name__ == "__main__":
    unittest.main()
