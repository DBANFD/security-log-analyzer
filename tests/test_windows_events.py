import gzip
import io
import json
import os
import sqlite3
import shutil
import subprocess
import tempfile
import threading
import unittest
from xml.etree import ElementTree as ET
from pathlib import Path
from unittest.mock import patch

from security_log_analyzer.core import create_case, validate_case, import_file, query_events, summary, normalize, offset_zone, Cancelled
from security_log_analyzer.windows_events import event_xml_record, decode_record, windows_records, xml_records
from security_log_analyzer.reports import export_csv, export_report

FIXTURE = Path(__file__).resolve().parents[1] / 'samples/windows-demo.xml'


class WindowsFormatTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = self.root / 'case.sqlite'
        create_case(self.case)

    def test_xml_auth_sysmon_and_metadata(self):
        result = import_file(self.case, FIXTURE)
        self.assertEqual(result['records'], 2)
        events = query_events(self.case)
        self.assertEqual(events[0]['src_ip'], '203.0.113.42')
        self.assertEqual(events[0]['event_id'], '4625')
        self.assertEqual(events[0]['failed'], 1)
        self.assertEqual(events[0]['channel'], 'Security')
        self.assertEqual(events[0]['record_id'], '1001')
        self.assertEqual(events[1]['dst_ip'], '192.0.2.10')
        self.assertEqual(events[1]['failed'], 0)
        self.assertIn('event_xml', json.loads(events[0]['raw']))

    def test_windows_event_id_is_provider_scoped(self):
        record = next(xml_records(io.BytesIO(FIXTURE.read_bytes())))[1]
        record['provider'] = 'Other-Provider'
        record['message'] = 'Reference to 4625, not a Security audit event'
        self.assertEqual(normalize(record, offset_zone('+00:00'))[0]['failed'], 0)

    def test_event_filters_and_exports(self):
        import_file(self.case, FIXTURE)
        self.assertEqual(len(query_events(self.case, event_id='4625')), 1)
        self.assertEqual(len(query_events(self.case, provider='Microsoft-Windows-Sysmon')), 1)
        self.assertEqual(len(query_events(self.case, search='Sysmon')), 1)
        self.assertEqual(len(query_events(self.case, event_id="' OR 1=1--")), 0)
        export_csv(self.case, self.root / 'out.csv', event_id='4625')
        self.assertIn('decode_warning', (self.root / 'out.csv').read_text(encoding='utf-8-sig'))
        export_report(self.case, self.root / 'report.html', [])
        self.assertIn('decode_warnings', (self.root / 'report.html').read_text(encoding='utf-8'))

    def test_xml_utf16_and_gzip(self):
        xml = FIXTURE.read_text(encoding='utf-8').replace('encoding="UTF-8"', 'encoding="UTF-16"')
        path = self.root / 'events.xml.gz'
        with gzip.open(path, 'wb') as f:
            f.write(xml.encode('utf-16'))
        self.assertEqual(import_file(self.case, path)['records'], 2)

    def test_xml_dtd_rejected_even_utf16(self):
        for encoding in ('utf-8', 'utf-16', 'utf-32'):
            data = '<!DOCTYPE Events [<!ENTITY x "secret">]><Events/>'.encode(encoding)
            with self.assertRaises((ValueError, ET.ParseError)):
                list(xml_records(io.BytesIO(data)))

    def test_malformed_xml_rolls_back(self):
        path = self.root / 'broken.xml'
        path.write_bytes(FIXTURE.read_bytes().replace(b'</Events>', b''))
        with self.assertRaises(Exception):
            import_file(self.case, path)
        self.assertEqual(summary(self.case)['events'], 0)

    def test_wrong_xml_schema_rejected(self):
        with self.assertRaises(ValueError):
            list(xml_records(io.BytesIO(b'<Settings><Value>test</Value></Settings>')))

    def test_nested_userdata_event_is_not_a_second_record(self):
        data = b'<Events><Event><System><EventID>1</EventID></System><UserData><Event><Message>test</Message></Event></UserData></Event></Events>'
        records = list(xml_records(io.BytesIO(data)))
        self.assertEqual(len(records), 1)
        self.assertIn('test', records[0][1]['message'])

    def test_payload_cannot_overwrite_metadata(self):
        xml = '<Event><System><Provider Name="expected"/><EventID>7</EventID><Computer>real</Computer></System><EventData><Data Name="provider">fake</Data><Data Name="host">fake</Data><Data Name="EventID">4625</Data></EventData></Event>'
        record = event_xml_record(xml)
        self.assertEqual(record['provider'], 'expected')
        self.assertEqual(record['host'], 'real')
        self.assertEqual(record['event_id'], '7')

    def test_etw_string_data_and_guid_fallback(self):
        record = event_xml_record('<Event><System><Provider Guid="{test}"/><EventID>0</EventID></System><Data>synthetic payload</Data></Event>')
        self.assertEqual(record['provider'], '{test}')
        self.assertIn('synthetic payload', record['message'])

    def test_decode_warning_retains_metadata(self):
        record = decode_record({'timestamp': '2026-01-01T00:00:00Z', 'event_id': 42, 'provider': 'test', 'xml': '', 'warnings': ['Missing provider resources'], 'unrendered_properties': ['opaque']})
        path = self.root / 'decoded.jsonl'
        path.write_text(json.dumps(record), encoding='utf-8')
        result = import_file(self.case, path)
        self.assertEqual(result['decode_warnings'], 1)
        self.assertEqual(summary(self.case)['imports'][0]['decode_warnings'], 1)
        self.assertEqual(query_events(self.case)[0]['event_id'], '42')

    def test_tsv(self):
        path = self.root / 'events.tsv'
        path.write_text('Timestamp\tEventID\tProvider\n2026-01-01T00:00:00Z\t7\tDemo\n', encoding='utf-8')
        self.assertEqual(import_file(self.case, path)['records'], 1)
        self.assertEqual(query_events(self.case)[0]['provider'], 'Demo')

    def test_schema_one_migration_preserves_rows(self):
        old = self.root / 'old.sqlite'
        db = sqlite3.connect(old)
        db.executescript("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT); INSERT INTO metadata VALUES('schema_version','1'); CREATE TABLE imports(id INTEGER PRIMARY KEY); CREATE TABLE events(id INTEGER PRIMARY KEY,import_id INTEGER,timestamp TEXT,raw TEXT); INSERT INTO events VALUES(1,1,'2026-01-01','preserve-me');")
        db.close()
        validate_case(old)
        validate_case(old)
        db = sqlite3.connect(old)
        try:
            self.assertEqual(db.execute('SELECT raw,provider FROM events').fetchone(), ('preserve-me', ''))
            self.assertEqual(db.execute('SELECT value FROM metadata').fetchone()[0], '3')
            self.assertIn('annotations', [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")])
            self.assertIn('decode_warnings', [r[1] for r in db.execute('PRAGMA table_info(imports)')])
        finally:
            db.close()

    def test_non_windows_explanation(self):
        with patch('security_log_analyzer.windows_events.os.name', 'posix'):
            with self.assertRaisesRegex(ValueError, 'requires Windows'):
                list(windows_records('test.evtx'))

    def test_native_cancel_before_launch(self):
        cancel = threading.Event()
        cancel.set()
        file = self.root / 'test.etl'
        file.write_bytes(b'data')
        with self.assertRaises(Cancelled):
            import_file(self.case, file, cancel=cancel)
        self.assertEqual(summary(self.case)['imports'], [])

    @unittest.skipUnless(os.name == 'nt', 'Windows native reader')
    def test_invalid_binary_rolls_back(self):
        for extension in ('evtx', 'etl'):
            file = self.root / ('bad.' + extension)
            file.write_bytes(b'not a Windows event file')
            with self.assertRaises(ValueError):
                import_file(self.case, file)
        self.assertEqual(summary(self.case)['events'], 0)
        self.assertEqual(summary(self.case)['imports'], [])


@unittest.skipUnless(os.name == 'nt' and os.environ.get('SLA_NATIVE_FIXTURES'), 'Set SLA_NATIVE_FIXTURES to a generated synthetic fixture directory')
class NativeRoundTripTests(unittest.TestCase):
    def test_etl_evtx_payload_and_timestamp_agreement(self):
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder) / 'native.sqlite'
            create_case(case)
            fixture = Path(os.environ['SLA_NATIVE_FIXTURES'])
            for name in ('synthetic.etl', 'synthetic.evtx'):
                result = import_file(case, fixture / name)
                self.assertGreaterEqual(result['records'], 6)
            rows = query_events(case, search='demo-1')
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]['timestamp'], rows[1]['timestamp'])
            self.assertIn('203.0.113.42', rows[0]['message'])
            self.assertTrue(rows[0]['decode_warning'])
            self.assertEqual(len(query_events(case, search='demo-')), 12)

    def test_literal_path_with_shell_metacharacters(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "synthetic [one] ' $x ; unicode-å.evtx"
            shutil.copy2(Path(os.environ['SLA_NATIVE_FIXTURES']) / 'synthetic.evtx', path)
            records = list(windows_records(path))
            self.assertGreaterEqual(len(records), 6)

    def test_cancel_after_first_event_cleans_processes(self):
        real_popen = subprocess.Popen
        for extension in ('evtx', 'etl'):
            processes = []
            cancel = threading.Event()
            def popen(*args, **kwargs):
                process = real_popen(*args, **kwargs)
                processes.append(process)
                return process
            def check():
                if cancel.is_set():
                    raise Cancelled('test cancellation')
            with patch('security_log_analyzer.windows_events.subprocess.Popen', side_effect=popen):
                source = windows_records(Path(os.environ['SLA_NATIVE_FIXTURES']) / ('synthetic.' + extension), check)
                try:
                    next(source)
                    cancel.set()
                    with self.assertRaises(Cancelled):
                        next(source)
                finally:
                    source.close()
            self.assertTrue(processes)
            self.assertTrue(all(p.poll() is not None for p in processes))


if __name__ == '__main__':
    unittest.main()
