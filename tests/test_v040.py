import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from security_log_analyzer.core import (create_case, validate_case, import_file, analyze, connect, query_events,
                                        add_annotation, list_annotations, delete_annotation, source_timeline)
from security_log_analyzer.reports import export_report

SEC = "Microsoft-Windows-Security-Auditing"


class WindowsRuleAndNoteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.case = self.root / "case.sqlite"
        create_case(self.case)

    def ingest(self, rows, name="events.jsonl"):
        path = self.root / name
        path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
        return import_file(self.case, path)

    def event(self, event_id, provider=SEC, host="dc1", minute=0):
        return {"TimeGenerated": f"2026-01-01T10:{minute:02d}:00Z", "Computer": host, "EventID": event_id, "Provider": provider, "Message": f"event {event_id}"}

    def rules(self, findings):
        return sorted((f["rule"], f["entity"], f["events"]) for f in findings if f["rule"] not in ("AUTH_BURST", "DEST_FANOUT", "LOCAL_IOC"))

    def test_windows_rules_match_event_id_and_exact_provider(self):
        self.ingest([
            self.event("1102"), self.event("104", "Microsoft-Windows-Eventlog", "srv1"),
            self.event("7045", "Service Control Manager", "srv1", 1), self.event("4697", host="srv2"),
            self.event("4728", minute=2), self.event("4732", minute=3), self.event("4756", host="dc2"),
            self.event("4720"), self.event("4698", host="ws1"),
            # Same IDs from a non-Windows provider or a generic CSV column must not trigger.
            self.event("1102", "ContosoApp"), self.event("7045", ""), self.event("4720", "Microsoft-Windows-Security-Auditing-Fake"),
        ])
        found = self.rules(analyze(self.case))
        self.assertEqual(found, sorted([
            ("LOG_CLEARED", "dc1", 1), ("LOG_CLEARED", "srv1", 1),
            ("NEW_SERVICE", "srv1", 1), ("NEW_SERVICE", "srv2", 1),
            ("PRIV_GROUP_CHANGE", "dc1", 2), ("PRIV_GROUP_CHANGE", "dc2", 1),
            ("ACCOUNT_CREATED", "dc1", 1), ("SCHEDULED_TASK", "ws1", 1),
        ]))

    def test_windows_rules_can_be_disabled_and_pivot_targets_evidence(self):
        self.ingest([self.event("1102"), self.event("1102", minute=5)])
        self.assertEqual(self.rules(analyze(self.case, windows_rules=False)), [])
        finding = [f for f in analyze(self.case) if f["rule"] == "LOG_CLEARED"][0]
        self.assertEqual(finding["pivot"], {"event_id": "1102", "search": "dc1"})
        self.assertEqual(len(query_events(self.case, **finding["pivot"])), 2)

    def test_unknown_host_pivot_does_not_search_placeholder(self):
        row = self.event("4720")
        del row["Computer"]
        self.ingest([row])
        finding = [f for f in analyze(self.case) if f["rule"] == "ACCOUNT_CREATED"][0]
        self.assertEqual(finding["entity"], "(unknown host)")
        self.assertEqual(finding["pivot"]["search"], "")

    def test_annotations_add_list_delete_and_validation(self):
        self.ingest([self.event("4720"), self.event("4698", minute=1)])
        first, second = [e["id"] for e in query_events(self.case)]
        note_id = add_annotation(self.case, first, "suspicious", "Created outside change window")
        add_annotation(self.case, second, "", "Benign: patch task")
        notes = list_annotations(self.case)
        self.assertEqual([(n["event_ref"], n["tag"]) for n in notes], [(first, "suspicious"), (second, "")])
        self.assertEqual(notes[0]["host"], "dc1")
        self.assertEqual(len(list_annotations(self.case, second)), 1)
        with self.assertRaises(ValueError):
            add_annotation(self.case, first, " ", " ")
        with self.assertRaises(ValueError):
            add_annotation(self.case, 99999, "x")
        with self.assertRaises(ValueError):
            add_annotation(self.case, first, "x" * 65)
        delete_annotation(self.case, note_id)
        self.assertEqual(len(list_annotations(self.case)), 1)
        with self.assertRaises(ValueError):
            delete_annotation(self.case, note_id)

    def test_schema_2_case_migrates_and_keeps_events(self):
        self.ingest([self.event("4720")])
        with connect(self.case) as db:
            db.execute("DROP TABLE annotations")
            db.execute("UPDATE metadata SET value='2' WHERE key='schema_version'")
        validate_case(self.case)
        with connect(self.case) as db:
            self.assertEqual(db.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()[0], "3")
            self.assertEqual(db.execute("SELECT count(*) FROM events").fetchone()[0], 1)
        add_annotation(self.case, query_events(self.case)[0]["id"], "migrated")
        validate_case(self.case)  # Idempotent on schema 3.

    def test_source_timeline_splits_hours_by_file(self):
        self.ingest([self.event("4720"), self.event("4720", minute=30)], "a.jsonl")
        self.ingest([{**self.event("4698"), "TimeGenerated": "2026-01-01T11:15:00Z"}], "b.jsonl")
        timeline = source_timeline(self.case)
        self.assertEqual(timeline["hours"], ["2026-01-01T10", "2026-01-01T11"])
        self.assertEqual([(s["name"], s["counts"]) for s in timeline["sources"]],
                         [("a.jsonl", {"2026-01-01T10": 2}), ("b.jsonl", {"2026-01-01T11": 1})])
        self.assertEqual(source_timeline(self.case, hours=1)["hours"], ["2026-01-01T11"])

    def test_reports_include_notes_windows_findings_and_escape_html(self):
        self.ingest([self.event("1102")])
        add_annotation(self.case, query_events(self.case)[0]["id"], "<b>tag</b>", "note & detail")
        findings = analyze(self.case)
        html_path, json_path = self.root / "r.html", self.root / "r.json"
        export_report(self.case, html_path, findings, {"windows_rules": True})
        export_report(self.case, json_path, findings, {"windows_rules": True})
        page = html_path.read_text(encoding="utf-8")
        self.assertIn("LOG_CLEARED", page)
        self.assertIn("&lt;b&gt;tag&lt;/b&gt;", page)
        self.assertIn("Timeline by source", page)
        self.assertNotIn(chr(0x2014), page)
        data = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(data["annotations"][0]["note"], "note & detail")
        self.assertEqual(data["source_timeline"]["sources"][0]["name"], "events.jsonl")

    def test_cli_note_timeline_and_rule_toggle(self):
        self.ingest([self.event("1102")])
        event_id = str(query_events(self.case)[0]["id"])
        def cli(*args):
            return subprocess.run([sys.executable, "-m", "security_log_analyzer", *args], capture_output=True, text=True, check=True).stdout
        self.assertIn("Saved annotation", cli("note", "add", str(self.case), event_id, "--tag", "review", "--text", "check"))
        self.assertEqual(json.loads(cli("note", "list", str(self.case)))[0]["tag"], "review")
        self.assertEqual(json.loads(cli("timeline", str(self.case)))["hours"], ["2026-01-01T10"])
        self.assertIn("1 findings", cli("report", str(self.case), str(self.root / "on.json")))
        self.assertIn("0 findings", cli("report", str(self.case), str(self.root / "off.json"), "--no-windows-rules"))


if __name__ == "__main__":
    unittest.main()
