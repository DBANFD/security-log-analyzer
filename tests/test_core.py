import csv
import gzip
import json
import tempfile
import threading
import unittest
from pathlib import Path
from security_log_analyzer.core import (create_case, import_file, summary, query_events, analyze, load_indicators, parse_time, offset_zone, clean_ip, ip_scope, connect, Cancelled, MAX_RECORD)
from security_log_analyzer.reports import export_csv, export_report


class CaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.case = self.root / "case.sqlite"
        create_case(self.case)

    def file(self, name, content):
        path = self.root / name
        path.write_text(content, encoding="utf-8")
        return path

    def ingest_json(self, rows, name="events.jsonl", **kwargs):
        return import_file(self.case, self.file(name, "\n".join(json.dumps(r) for r in rows)), **kwargs)

    def test_defender_csv_and_embedded_newline(self):
        path = self.root / "defender.csv"
        with path.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "DeviceName", "LocalIP", "RemoteIP", "ActionType", "ProcessCommandLine"])
            writer.writerow(["2026-01-01T12:00:00Z", "demo-host", "10.1.1.2", "8.8.8.8", "ConnectionSuccess", "line1\nline2, comma"])
        result = import_file(self.case, path)
        self.assertEqual(result["records"], 1)
        event = query_events(self.case)[0]
        self.assertEqual(event["host"], "demo-host")
        self.assertEqual(event["dst_ip"], "8.8.8.8")
        self.assertEqual(event["message"], "line1\nline2, comma")

    def test_sentinel_json_and_bad_records(self):
        path = self.file("sentinel.jsonl", '{"TimeGenerated":"2026-01-01T12:00:00+02:00","Computer":"demo","SourceIP":"2001:4860:4860::8888"}\ninvalid\n[]\n')
        result = import_file(self.case, path)
        self.assertEqual(result["rejected"], 2)
        self.assertEqual(query_events(self.case)[0]["timestamp"], "2026-01-01T10:00:00.000+00:00")

    def test_timezone_and_epoch(self):
        stamp, assumed = parse_time("2026-01-01T12:00:00", offset_zone("+01:00"))
        self.assertEqual(stamp, "2026-01-01T11:00:00.000+00:00")
        self.assertTrue(assumed)
        self.assertEqual(parse_time("1700000000000", offset_zone("+00:00"))[0], "2023-11-14T22:13:20.000+00:00")
        with self.assertRaises(ValueError):
            offset_zone("+02:99")

    def test_syslog_missing_year_preserved(self):
        result = import_file(self.case, self.file("ssh.log", "<34>Nov  5 09:01:00 demo sshd: Failed password for invalid user test from 203.0.113.1 port 22\n"))
        self.assertEqual(result["undated"], 1)
        self.assertEqual(query_events(self.case)[0]["src_ip"], "203.0.113.1")
        self.assertEqual(analyze(self.case, failure_threshold=2), [])

    def test_syslog_year_and_iso(self):
        self.file("ssh.log", "Nov  5 09:01:00 demo sshd: Failed password from 203.0.113.1\n<34>1 2026-11-05T10:02:00Z demo sshd - - - authentication failed from 203.0.113.1\n")
        result = import_file(self.case, self.root / "ssh.log", year=2026, offset="+01:00")
        self.assertEqual(result["assumed"], 1)
        self.assertEqual(query_events(self.case)[0]["timestamp"], "2026-11-05T08:01:00.000+00:00")

    def test_firewall_and_deny_not_auth(self):
        import_file(self.case, self.file("firewall.log", 'date=2026-01-01 time=12:00:00 devname="demo fw" srcip=10.0.0.1 dstip=8.8.8.8 action=deny msg="policy denied"\n'))
        event = query_events(self.case)[0]
        self.assertEqual(event["host"], "demo fw")
        self.assertEqual(event["failed"], 0)

    def test_cross_source_auth_and_boundary(self):
        rows = [{"Timestamp": f"2026-01-01T00:0{i}:00Z", "SourceIP": "203.0.113.1", "ActionType": "LogonFailed"} for i in range(5)]
        self.ingest_json(rows[:3], "a.jsonl")
        self.ingest_json(rows[3:], "b.jsonl")
        findings = analyze(self.case)
        self.assertEqual(findings[0]["events"], 5)
        self.assertEqual(findings[0]["sources"], 2)
        self.ingest_json([{"Timestamp": "2026-01-01T00:05:00Z", "SourceIP": "203.0.113.1", "ActionType": "LogonFailed"}], "c.jsonl")
        self.assertEqual(analyze(self.case)[0]["events"], 5)

    def test_fanout_and_ioc(self):
        self.ingest_json([{"Timestamp": "2026-01-01T00:00:00Z", "src": "10.0.0.1", "dst": f"192.0.2.{i}"} for i in range(1, 21)])
        indicators = load_indicators(self.file("ioc.txt", "# demo\n10.0.0.0/24\n"))
        findings = analyze(self.case, indicators)
        self.assertEqual({f["rule"] for f in findings}, {"DEST_FANOUT", "LOCAL_IOC"})
        self.assertEqual(next(f for f in findings if f["rule"] == "LOCAL_IOC")["events"], 20)

    def test_duplicate_and_cancel_rollback(self):
        path = self.file("x.log", "a line\n")
        import_file(self.case, path)
        with self.assertRaises(ValueError):
            import_file(self.case, path)
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(Cancelled):
            import_file(self.case, path, cancel=cancel)
        self.assertEqual(summary(self.case)["events"], 1)

    def test_mid_import_cancel_rolls_back(self):
        path = self.file("many.log", "one line\n" * 4000)
        cancel = threading.Event()
        def progress(text):
            if "2,000 events" in text:
                cancel.set()
        with self.assertRaises(Cancelled):
            import_file(self.case, path, cancel=cancel, progress=progress)
        self.assertEqual(summary(self.case)["events"], 0)
        self.assertEqual(summary(self.case)["imports"], [])

    def test_gzip(self):
        path = self.root / "events.jsonl.gz"
        with gzip.open(path, "wt", encoding="utf-8") as f:
            f.write('{"Message":"synthetic"}\n')
        self.assertEqual(import_file(self.case, path)["records"], 1)

    def test_corrupt_utf8_rolls_back(self):
        path = self.root / "bad.log"
        path.write_bytes(b"good\n\xff\n")
        with self.assertRaises(UnicodeDecodeError):
            import_file(self.case, path)
        self.assertEqual(summary(self.case)["events"], 0)

    def test_oversized_json_record(self):
        path = self.file("large.jsonl", "x" * (MAX_RECORD + 5) + '\n{"Message":"ok"}\n')
        result = import_file(self.case, path)
        self.assertEqual((result["records"], result["rejected"]), (1, 1))

    def test_filters_pagination_and_injection(self):
        self.ingest_json([{"message": text, "src": "10.0.0.1"} for text in ("100%", "100_", "O'Reilly")])
        self.assertEqual(len(query_events(self.case, search="%")), 1)
        self.assertEqual(len(query_events(self.case, search="' OR 1=1 --")), 0)
        page = query_events(self.case, limit=2)
        self.assertEqual(len(query_events(self.case, after=page[-1]["id"])), 1)
        with self.assertRaises(ValueError):
            query_events(self.case, ip="bad")
        with self.assertRaises(ValueError):
            query_events(self.case, start="2026-02-01", end="2026-01-01")

    def test_html_and_csv_export_safety(self):
        self.ingest_json([{"host": "<script>alert(1)</script>", "message": "=1+1", "src": "10.0.0.1"}])
        output = self.root / "report.html"
        export_report(self.case, output, [{"rule": "LOCAL_IOC", "entity": "<script>"}])
        text = output.read_text(encoding="utf-8")
        self.assertNotIn("<script>", text)
        self.assertIn("&lt;script&gt;", text)
        csv_path = self.root / "out.csv"
        self.assertEqual(export_csv(self.case, csv_path), 1)
        with csv_path.open(encoding="utf-8-sig", newline="") as f:
            self.assertEqual(list(csv.DictReader(f))[0]["message"], "'=1+1")
        with self.assertRaises(ValueError):
            export_report(self.case, self.case, [])
        with self.assertRaises(ValueError):
            export_csv(self.case, self.case)

    def test_invalid_csv_and_json_array(self):
        with self.assertRaises(ValueError):
            import_file(self.case, self.file("dupe.csv", "a,a\n1,2\n"))
        with self.assertRaises(ValueError):
            import_file(self.case, self.file("array.json", "[]"))

    def test_ip_classification(self):
        self.assertEqual(clean_ip("::ffff:192.0.2.1"), "192.0.2.1")
        self.assertEqual(ip_scope("127.0.0.1"), "non-global")
        self.assertEqual(ip_scope("8.8.8.8"), "global")

    def test_no_findings_does_not_claim_clean(self):
        self.ingest_json([{"message": "nothing"}])
        output = self.root / "empty.html"
        export_report(self.case, output, [])
        self.assertIn("does not establish absence", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
