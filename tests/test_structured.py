import gzip
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path

from security_log_analyzer.core import create_case, import_file, query_events, summary, analyze, Cancelled
from security_log_analyzer.json_stream import json_records, nested_record, MAX_EVENT
from security_log_analyzer.structured_logs import parse_cef, parse_leef, W3CParser


class StructuredTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.case = self.root / 'case.sqlite'
        create_case(self.case)

    def ingest(self, text, name='sample.log', **kwargs):
        path = self.root / name
        path.write_text(text, encoding='utf-8')
        return import_file(self.case, path, **kwargs)

    def test_cef_escaped_header_and_extension(self):
        line = r'CEF:0|Demo\|Vendor|Firewall|1|42|Test \\ path|7|src=203.0.113.42 dst=192.0.2.1 rt=1768471200000 msg=hello foo\=bar\nnext \\ end act=blocked'
        row = parse_cef(line)
        self.assertEqual(row['provider'], 'Demo|Vendor/Firewall')
        self.assertEqual(row['header']['name'], 'Test \\ path')
        self.assertEqual(row['message'], 'hello foo=bar\nnext \\ end')
        self.assertEqual(row['action'], 'blocked')
        self.assertEqual(row['raw_line'], line)

    def test_cef_mixed_syslog_detection_and_time(self):
        self.ingest('Jan 15 10:00:00 fw CEF:0|Demo|FW|1|42|Activity|5|src=203.0.113.42 dst=192.0.2.1 msg=authentication failed\n', year=2026)
        row = query_events(self.case)[0]
        self.assertEqual(row['host'], 'fw')
        self.assertEqual(row['timestamp'], '2026-01-15T10:00:00.000+00:00')
        self.assertEqual(row['failed'], 1)

    def test_cef_duplicate_and_bad_header_are_retained_with_warning(self):
        result = self.ingest('CEF:0|Demo|FW|1|42|Activity|5|src=10.0.0.1 src=10.0.0.2\nCEF:0|broken\n')
        self.assertEqual(result['records'], 2)
        self.assertEqual(result['decode_warnings'], 2)
        self.assertEqual(query_events(self.case)[0]['src_ip'], '10.0.0.1')

    def test_cef_equals_pipe_and_spaces(self):
        row = parse_cef(r'CEF:0|V|P|1|id|a=b|Low|msg=spaces and | pipe url=a\=b act=blocked by policy')
        self.assertEqual(row['message'], 'spaces and | pipe')
        self.assertEqual(row['attributes']['url'], 'a=b')
        self.assertEqual(row['action'], 'blocked by policy')

    def test_cef_numeric_vendor_id_not_auth(self):
        self.ingest('CEF:0|Vendor|FW|1|4625|Routine|1|src=10.0.0.1\n')
        self.assertEqual(query_events(self.case)[0]['failed'], 0)

    def test_leef_one_tabs_preserves_spaces_equals_backslashes(self):
        line = 'LEEF:1.0|Demo|FW|1|login|src=203.0.113.42\tdst=192.0.2.1\tusrName=demo user\tmsg=C:\\temp\\new x=y\tsev=7'
        row = parse_leef(line)
        self.assertEqual(row['user'], 'demo user')
        self.assertEqual(row['message'], 'C:\\temp\\new x=y')
        self.assertEqual(row['dst_ip'], '192.0.2.1')

    def test_leef_two_literal_and_hex_delimiters(self):
        for delimiter in ('^', '0x5E', '0x005e'):
            row = parse_leef(f'LEEF:2.0|Demo|FW|1|test|{delimiter}|src=203.0.113.42^msg=two words')
            self.assertEqual(row['src_ip'], '203.0.113.42')
            self.assertEqual(row['message'], 'two words')

    def test_leef_devtime_format(self):
        self.ingest('LEEF:2.0|Demo|FW|1|test|^|devTime=Jan 15 2026 10:00:00^devTimeFormat=MMM dd yyyy HH:mm:ss^src=203.0.113.42', offset='+01:00')
        self.assertEqual(query_events(self.case)[0]['timestamp'], '2026-01-15T09:00:00.000+00:00')

    def test_leef_unsupported_date_warns(self):
        result = self.ingest('LEEF:1.0|Demo|FW|1|test|devTime=15th Jan\tdevTimeFormat=custom')
        self.assertEqual(result['undated'], 1)
        self.assertEqual(result['decode_warnings'], 1)

    def test_leef_bad_delimiter_retained(self):
        result = self.ingest('LEEF:2.0|Demo|FW|1|test|two|src=10.0.0.1')
        self.assertEqual(result['decode_warnings'], 1)

    def test_w3c_fields_changes_utc_and_original_values(self):
        text = '#Software: Microsoft Internet Information Services\n#Version: 1.0\n#Fields: date time c-ip s-ip cs-method cs-uri-stem cs-uri-query sc-status\n2026-01-15 10:00:00 203.0.113.42 10.0.0.1 GET /a q=a%20b 200\n#Fields: c-ip date time sc-status cs-method cs-uri-stem\n203.0.113.43 2026-01-15 10:01:00 404 GET /4625\n'
        result = self.ingest(text, offset='+09:00')
        self.assertEqual(result['records'], 2)
        self.assertEqual(result['assumed'], 0)
        rows = query_events(self.case)
        self.assertEqual(rows[0]['timestamp'], '2026-01-15T10:00:00.000+00:00')
        self.assertIn('/a?q=a%20b', rows[0]['message'])
        self.assertEqual(rows[1]['severity'], 'warning')
        self.assertEqual(rows[1]['failed'], 0)

    def test_w3c_malformed_lines_retained(self):
        result = self.ingest('#Fields: date time c-ip\n2026-01-15 10:00:00\n#Fields: date date\nwrong fields\n')
        self.assertEqual(result['records'], 3)
        self.assertEqual(result['decode_warnings'], 3)

    def test_w3c_quoted_field_missing_and_bad_dates(self):
        self.ingest('#Fields: date time c-ip cs(User-Agent) sc-status\n2026-01-15 10:00:00 - "Demo Agent" 503\ninvalid 10:00:00 203.0.113.42 - 200\n')
        rows = query_events(self.case)
        self.assertEqual(rows[0]['src_ip'], '')
        self.assertIn('Demo Agent', rows[0]['message'])
        self.assertEqual(rows[0]['severity'], 'error')
        self.assertTrue(rows[1]['decode_warning'])

    def test_force_parser_and_text_override(self):
        self.ingest('no fields header', name='one.log', input_format='w3c')
        self.ingest('CEF:0|broken', name='two.log', input_format='text')
        rows = query_events(self.case)
        self.assertTrue(rows[0]['decode_warning'])
        self.assertFalse(rows[1]['decode_warning'])

    def test_nested_json_array_common_paths_and_original(self):
        original = {'@timestamp':'2026-01-15T10:00:00Z', 'host':{'name':'demo'}, 'source':{'ip':'203.0.113.42'}, 'destination':{'ip':'192.0.2.1'}, 'user':{'name':'test'}, 'event':{'action':'connection','code':3}, 'details':{'opaque':[1,2]}}
        self.ingest(json.dumps([original]), name='events.json')
        row = query_events(self.case)[0]
        self.assertEqual(row['host'], 'demo')
        self.assertEqual(row['src_ip'], '203.0.113.42')
        self.assertEqual(row['event_id'], '3')
        self.assertEqual(json.loads(row['raw'])['original'], original)

    def test_wrapped_json_and_elastic_source(self):
        self.ingest(json.dumps({'hits':{'total':1,'hits':[{'_source':{'source.ip':'203.0.113.42','host.name':'demo'}}]}}), name='elastic.json')
        row = query_events(self.case)[0]
        self.assertEqual(row['src_ip'], '203.0.113.42')
        self.assertEqual(json.loads(row['raw'])['json_path'], '/hits/hits/0')

    def test_custom_pointer_escaped_keys(self):
        self.ingest('{"a/b":{"~x":[{"Message":"ok"}]},"metadata":123}', name='custom.json', json_path='/a~1b/~0x')
        self.assertEqual(query_events(self.case)[0]['message'], 'ok')

    def test_root_object_and_explicit_root(self):
        self.ingest('{"outer":{"TimeGenerated":"2026-01-15T10:00:00Z","Message":"one"}}', name='object.json')
        self.ingest('{"events":[],"message":"whole event"}', name='root.json', json_path='$')
        self.assertEqual(summary(self.case)['events'], 2)
        self.assertEqual(query_events(self.case)[0]['message'], 'one')

    def test_ambiguous_arrays_rollback_and_explicit_selection(self):
        text = '{"events":[{"Message":"one"}],"records":[{"Message":"two"}]}'
        with self.assertRaisesRegex(ValueError, 'Multiple JSON'):
            self.ingest(text, name='ambiguous.json')
        self.assertEqual(summary(self.case)['events'], 0)
        self.ingest(text, name='ambiguous.json', json_path='/records')
        self.assertEqual(query_events(self.case)[0]['message'], 'two')

    def test_json_malformed_trailing_and_duplicate_keys(self):
        for index, text in enumerate(('[{"message":"ok"},]', '[{"message":"ok"}]junk', '{"events":[{"message":"ok"}],}', '[{"message":"x","message":"y"}]', '[NaN]', '{"x":1,"x":2}')):
            with self.assertRaises(ValueError, msg=text):
                self.ingest(text, name=f'bad{index}.json')
        self.assertEqual(summary(self.case)['imports'], [])

    def test_json_nonobjects_counted_rejected(self):
        result = self.ingest('[1,null,"text",{"message":"ok"}]', name='items.json')
        self.assertEqual(result['records'], 1)
        self.assertEqual(result['rejected'], 3)

    def test_jsonl_nested_and_invalid_lines(self):
        result = self.ingest('{"host":{"name":"demo"},"source":{"ip":"203.0.113.42"}}\ninvalid\n', name='nested.jsonl')
        self.assertEqual(result['rejected'], 1)
        self.assertEqual(query_events(self.case)[0]['host'], 'demo')

    def test_ambiguous_nested_leaf_left_blank(self):
        record = nested_record({'before':{'timestamp':'2026-01-01'}, 'after':{'timestamp':'2026-02-01'}})
        self.assertNotIn('timestamp', record)
        self.assertIn('Ambiguous nested timestamp', record['decode_warning'])

    def test_json_array_values_not_arbitrarily_flattened(self):
        record = nested_record({'addresses':[{'sourceip':'203.0.113.42'}]})
        self.assertNotIn('src_ip', record)

    def test_json_oversize_and_depth_fail(self):
        for index, text in enumerate(('[{"message":"'+'x'*MAX_EVENT+'"}]', '['*66+'0'+']'*66)):
            with self.assertRaises(ValueError):
                self.ingest(text, name=f'large{index}.json')
        self.assertEqual(summary(self.case)['events'], 0)

    def test_json_missing_pointer_and_invalid_pointer(self):
        for pointer in ('/missing', 'data.events', '/bad~2key'):
            with self.assertRaises(ValueError):
                self.ingest('{"events":[{"message":"ok"}]}', name='path.json', json_path=pointer)

    def test_json_chunk_boundary_and_bounded_reads(self):
        class SmallStream(io.StringIO):
            def read(self, size=-1):
                if size < 0:
                    raise AssertionError('Unbounded read')
                return super().read(min(size, 7))
        text = '{"events":[{"message":"a\\\"b\\\\c"},{"source":{"ip":"203.0.113.42"}}]}'
        rows = list(json_records(SmallStream(text)))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][1]['message'], 'a"b\\c')

    def test_gzip_structured_formats(self):
        for name, content in (('one.cef.gz', 'CEF:0|V|P|1|1|test|1|msg=ok'), ('two.json.gz','{"value":[{"message":"ok"}]}')):
            path = self.root / name
            with gzip.open(path,'wt',encoding='utf-8') as f:
                f.write(content)
            self.assertEqual(import_file(self.case,path)['records'],1)

    def test_json_cancel_rolls_back_after_batch(self):
        cancel = threading.Event()
        def progress(text):
            if '2,000 events' in text:
                cancel.set()
        with self.assertRaises(Cancelled):
            self.ingest('['+','.join('{"message":"ok"}' for _ in range(2100))+']', name='many.json', cancel=cancel, progress=progress)
        self.assertEqual(summary(self.case)['events'], 0)

    def test_json_late_syntax_error_rolls_back_written_batch(self):
        with self.assertRaises(ValueError):
            self.ingest('['+','.join('{"message":"ok"}' for _ in range(2100))+'] trailing', name='late.json')
        self.assertEqual(summary(self.case)['events'], 0)

    def test_json_capitalized_wrapper_and_iso_leef(self):
        self.ingest('{"Results":[{"TimeGenerated":"2026-01-01T00:00:00Z"}]}', name='capitalized.json')
        row = parse_leef("LEEF:2.0|Demo|FW|1|id|x5E|devTime=2026-01-15T10:00:00.123+0100^devTimeFormat=yyyy-MM-dd'T'HH:mm:ss.SSSZ")
        self.assertEqual(row['timestamp'], '2026-01-15T10:00:00.123+0100')
        self.assertEqual(summary(self.case)['events'], 1)

    def test_flat_json_aliases_and_separate_datetime_preserved(self):
        self.ingest('{"date":"2026-01-15","time":"10:00:00","DevName":"demo","SrcUser":"user"}', name='flat.jsonl')
        row = query_events(self.case)[0]
        self.assertEqual(row['timestamp'],'2026-01-15T10:00:00.000+00:00')
        self.assertEqual((row['host'],row['user']),('demo','user'))

    def test_cross_format_correlation_excludes_http_401(self):
        folder = Path(__file__).resolve().parents[1] / 'samples'
        for name in ('appliance-demo.cef','appliance-demo.leef','iis-demo.log','nested-demo.json'):
            import_file(self.case,folder/name)
        self.assertEqual(summary(self.case)['events'],9)
        finding = next(f for f in analyze(self.case,failure_threshold=3) if f['rule']=='AUTH_BURST')
        self.assertEqual((finding['events'],finding['sources']),(3,3))


if __name__ == '__main__':
    unittest.main()
