"""Streaming parsers, local case storage and transparent triage rules.

No network calls. Input is data, never evaluated or executed.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import ipaddress
import json
import re
import sqlite3
from contextlib import contextmanager, closing
from datetime import datetime, timezone, timedelta
from pathlib import Path

MAX_RECORD = 1024 * 1024
csv.field_size_limit(MAX_RECORD)

ALIASES = {
    "timestamp": ["timestamp", "timegenerated", "datetime", "eventtime", "@timestamp", "time"],
    "host": ["devicename", "computer", "hostname", "host", "dvc", "devname"],
    "user": ["accountupn", "accountname", "userprincipalname", "targetusername", "user", "username", "srcuser"],
    "src_ip": ["sourceip", "sourceipaddress", "srcip", "src", "ipaddress", "localip"],
    "dst_ip": ["destinationip", "destinationipaddress", "dstip", "dst", "remoteip"],
    "action": ["actiontype", "activity", "action", "eventid", "eventname"],
    "severity": ["severity", "loglevel", "level", "eventseverity"],
    "message": ["message", "syslogmessage", "description", "msg", "commandline", "processcommandline"],
    "provider": ["provider", "providername"],
    "event_id": ["eventid"],
    "channel": ["channel", "logname"],
    "record_id": ["recordid", "eventrecordid"],
    "decode_warning": ["decodewarning"],
}


class Cancelled(Exception):
    pass


@contextmanager
def connect(path):
    db = sqlite3.connect(path, timeout=60)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA cache_size=-16384")
    db.execute("PRAGMA temp_store=FILE")
    try:
        with db:
            yield db
    finally:
        db.close()


def create_case(path):
    if Path(path).exists():
        validate_case(path)
        return
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT);
        INSERT OR IGNORE INTO metadata VALUES ('schema_version','3');
        CREATE TABLE IF NOT EXISTS imports (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, sha256 TEXT UNIQUE NOT NULL,
            imported_at TEXT NOT NULL, records INTEGER DEFAULT 0,
            rejected INTEGER DEFAULT 0, undated INTEGER DEFAULT 0, assumed INTEGER DEFAULT 0,
            timezone_offset TEXT NOT NULL, syslog_year INTEGER, decode_warnings INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY, import_id INTEGER NOT NULL REFERENCES imports(id),
            line INTEGER NOT NULL, timestamp TEXT, host TEXT, user TEXT,
            src_ip TEXT, dst_ip TEXT, action TEXT, severity TEXT, message TEXT,
            failed INTEGER NOT NULL, raw TEXT NOT NULL,
            provider TEXT DEFAULT '', event_id TEXT DEFAULT '', channel TEXT DEFAULT '',
            record_id TEXT DEFAULT '', decode_warning TEXT DEFAULT '');
        CREATE INDEX IF NOT EXISTS events_time ON events(timestamp);
        CREATE INDEX IF NOT EXISTS events_src ON events(src_ip, timestamp);
        CREATE INDEX IF NOT EXISTS events_dst ON events(dst_ip, timestamp);
        CREATE INDEX IF NOT EXISTS events_host ON events(host, timestamp);
        """ + ANNOTATIONS_SQL)


ANNOTATIONS_SQL = """
        CREATE TABLE IF NOT EXISTS annotations (
            id INTEGER PRIMARY KEY, event_ref INTEGER NOT NULL REFERENCES events(id),
            tag TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS annotations_event ON annotations(event_ref);
"""
MAX_TAG = 64
MAX_NOTE = 4000


def validate_case(path):
    if not Path(path).is_file():
        raise ValueError("Case file does not exist.")
    with connect(path) as db:
        version = db.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()
        if not version or version[0] not in ("1", "2", "3"):
            raise ValueError("Unsupported case schema.")
        db.execute("SELECT import_id, timestamp, raw FROM events LIMIT 0")
        if version[0] in ("1", "2"):
            # Transactional additive migration; existing records are preserved.
            db.execute("BEGIN")
            if version[0] == "1":
                for name in ("provider", "event_id", "channel", "record_id", "decode_warning"):
                    db.execute(f"ALTER TABLE events ADD COLUMN {name} TEXT DEFAULT ''")
                db.execute("ALTER TABLE imports ADD COLUMN decode_warnings INTEGER DEFAULT 0")
            for statement in ANNOTATIONS_SQL.split(";"):
                if statement.strip():
                    db.execute(statement)
            db.execute("UPDATE metadata SET value='3' WHERE key='schema_version'")


def offset_zone(offset):
    if not re.fullmatch(r"[+-]\d{2}:\d{2}", offset):
        raise ValueError("Timezone must be a fixed offset such as +00:00 or +01:00.")
    hours, minutes = map(int, offset[1:].split(":"))
    if hours > 23 or minutes > 59:
        raise ValueError("Invalid timezone offset.")
    return timezone(timedelta(minutes=(hours * 60 + minutes) * (1 if offset[0] == "+" else -1)))


def parse_time(value, zone):
    value = str(value or "").strip()
    if not value:
        return None, False
    try:
        if re.fullmatch(r"\d{10}(?:\.\d+)?|\d{13}", value):
            number = float(value)
            if len(value.split(".")[0]) == 13:
                number /= 1000
            dt = datetime.fromtimestamp(number, timezone.utc)
        else:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        assumed = dt.tzinfo is None
        if assumed:
            dt = dt.replace(tzinfo=zone)
        return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds"), assumed
    except (ValueError, OverflowError, OSError):
        return None, False


def clean_ip(value):
    value = str(value or "").strip().strip("[]")
    try:
        addr = ipaddress.ip_address(value)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return str(addr)
    except ValueError:
        return ""


def ip_scope(value):
    try:
        addr = ipaddress.ip_address(value)
        return "global" if addr.is_global else "non-global"
    except ValueError:
        return "unknown"


def normalize(record, zone):
    fields = {re.sub(r"[ _-]", "", str(k).lower()): v for k, v in record.items()}
    result = {}
    for target, aliases in ALIASES.items():
        result[target] = next((str(fields[a]) for a in aliases if fields.get(a) is not None and str(fields[a]).strip()), "")
    if fields.get("date") and fields.get("time"):
        result["timestamp"] = f"{fields['date']}T{fields['time']}"
    stamp, assumed = parse_time(result["timestamp"], zone)
    if record.get("source_format") and result["timestamp"] and stamp is None:
        result["decode_warning"] = "; ".join(filter(None, (result["decode_warning"], "Timestamp could not be normalized; event retained as undated")))
    result["timestamp"] = stamp
    for key in ("src_ip", "dst_ip"):
        result[key] = clean_ip(result[key])
    # Network blocking is deliberately not classified as authentication failure.
    evidence = (result["action"] + " " + result["message"]).lower()
    result["failed"] = int(bool(re.search(r"failed password|authentication fail|logonfailed|loginfailed|failed login|logon failure|\b4625\b", evidence)))
    if record.get("windows_event"):
        # Windows event IDs are scoped to the provider, not globally unique.
        result["failed"] = int(result["provider"].lower() == "microsoft-windows-security-auditing" and result["event_id"] == "4625")
    elif record.get("source_format") in ("cef", "leef"):
        result["failed"] = int(bool(re.search(r"failed password|authentication fail|logonfailed|loginfailed|failed login|logon failure", evidence)))
    elif record.get("source_format") == "w3c":
        result["failed"] = 0  # HTTP status/URI text is not a Windows logon event.
    return result, assumed


KV = re.compile(r'(\w+)=(?:"((?:[^"\\]|\\.)*)"|([^\s]+))')


def parse_text(line, year=None):
    record = {m[0]: m[1] or m[2] for m in KV.findall(line)}
    iso = re.match(r"^(?:<\d+>)?(?:1 )?(\d{4}-\d{2}-\d{2}T\S+)\s+(\S+)\s+(.*)", line)
    classic = re.match(r"^(?:<\d+>)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)", line)
    if iso:
        record.update(timestamp=iso[1], host=iso[2], message=iso[3])
    elif classic:
        stamp = ""
        if year:
            months = {v: i for i, v in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
            month, day, clock = classic[1].split()
            if month in months:
                stamp = f"{year:04d}-{months[month]:02d}-{int(day):02d}T{clock}"
        record.update(timestamp=stamp, host=classic[2], message=classic[3])
    elif not record:
        record = {"message": line}
    if not any(k.lower() in ("src", "srcip", "sourceip") for k in record):
        match = re.search(r"\bfrom\s+([0-9a-fA-F:.]+)", line)
        if match:
            record["srcip"] = match[1]
    record.setdefault("message", line)
    return record


def records(path, year=None, check=lambda: None, input_format="auto", json_path=""):
    """Yield (logical record number, dict or None). Oversized lines are drained."""
    name = str(path).lower().removesuffix(".gz")
    if name.endswith((".evtx", ".etl")):
        if str(path).lower().endswith(".gz"):
            raise ValueError("Decompress EVTX/ETL before import; gzip is supported only for text/XML formats.")
        from .windows_events import windows_records
        yield from windows_records(path, check)
        return
    opener = gzip.open if str(path).lower().endswith(".gz") else open
    if name.endswith(".xml"):
        from .windows_events import xml_records
        with opener(path, "rb") as stream:
            yield from xml_records(stream, check)
        return
    with opener(path, "rt", encoding="utf-8-sig", errors="strict", newline="") as stream:
        if input_format == "json" or (input_format == "auto" and name.endswith(".json")):
            from .json_stream import json_records
            yield from json_records(stream, json_path, check)
        elif input_format == "auto" and name.endswith((".csv", ".tsv")):
            sample = stream.read(8192)
            stream.seek(0)
            try:
                dialect = csv.excel_tab if name.endswith(".tsv") else csv.Sniffer().sniff(sample, delimiters=",;\t")
            except csv.Error:
                dialect = csv.excel
            reader = csv.DictReader(stream, dialect=dialect)
            if not reader.fieldnames:
                raise ValueError("CSV requires a header row.")
            if len(reader.fieldnames) != len(set(reader.fieldnames)):
                raise ValueError("Duplicate CSV headers are ambiguous.")
            for n, row in enumerate(reader, 2):
                yield n, row if None not in row and all(v is not None for v in row.values()) and sum(len(v) for v in row.values()) <= MAX_RECORD else None
        else:
            from .structured_logs import W3CParser, parse_cef, parse_leef, warning_record
            from .json_stream import nested_record, strict_loads
            selected = input_format
            if selected == "auto":
                selected = next((suffix for suffix in ("cef", "leef", "w3c", "jsonl", "ndjson") if name.endswith("." + suffix)), "auto")
            w3c = W3CParser()
            w3c_active = selected == "w3c"
            n = 0
            while True:
                check()
                line = stream.readline(MAX_RECORD + 1)
                if not line:
                    break
                n += 1
                if len(line) > MAX_RECORD:
                    while line and not line.endswith("\n"):
                        check()
                        line = stream.readline(MAX_RECORD + 1)
                    yield n, None
                    continue
                if not line.strip():
                    continue
                if selected in ("jsonl", "ndjson"):
                    try:
                        row = strict_loads(line)
                        yield n, nested_record(row, f"line:{n}") if isinstance(row, dict) else None
                    except (ValueError, RecursionError):
                        yield n, None
                else:
                    line = line.rstrip("\r\n")
                    if selected == "auto" and line.startswith(("#Fields:", "#Software:", "#Version:")):
                        w3c_active = True
                    if w3c_active:
                        row = w3c.parse(line)
                        if row is not None:
                            yield n, row
                        continue
                    parser = selected if selected in ("cef", "leef") else ""
                    if selected == "auto":
                        match = re.search(r"(?<!\S)(CEF|LEEF):", line)
                        if match:
                            parser = match[1].lower()
                    if parser:
                        try:
                            yield n, (parse_cef if parser == "cef" else parse_leef)(line, parse_text(line, year))
                        except ValueError as exc:
                            yield n, warning_record(line, parser, str(exc))
                    else:
                        yield n, parse_text(line, year)


def import_file(case, path, offset="+00:00", year=None, progress=None, cancel=None, input_format="auto", json_path=""):
    zone = offset_zone(offset)
    if year is not None and not 1970 <= year <= 9999:
        raise ValueError("Syslog year must be between 1970 and 9999.")
    path = Path(path)
    validate_case(case)
    name = path.name.lower().removesuffix(".gz")
    if not name.endswith((".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".log", ".txt", ".syslog", ".evtx", ".etl", ".xml", ".cef", ".leef", ".w3c")):
        raise ValueError("Supported: CSV/TSV, JSON/JSONL, CEF/LEEF, W3C, LOG/TXT/SYSLOG, Windows Event XML, and EVTX/ETL (Windows only).")
    if input_format not in ("auto", "text", "cef", "leef", "w3c", "json", "jsonl"):
        raise ValueError("Unknown input format")
    if input_format != "auto" and name.endswith((".evtx", ".etl", ".xml")):
        raise ValueError("Use Auto for Windows EVTX/ETL/XML files")
    if json_path:
        from .json_stream import pointer_parts
        pointer_parts(json_path)
        if not (input_format == "json" or input_format == "auto" and name.endswith(".json")):
            raise ValueError("JSON path applies to JSON documents only; clear it for other formats")
    def check():
        if cancel and cancel.is_set():
            raise Cancelled("Import cancelled; this file was rolled back.")
    digest = hashlib.sha256()
    if progress:
        progress("Fingerprinting " + path.name)
    with path.open("rb") as source:
        while chunk := source.read(MAX_RECORD):
            check()
            digest.update(chunk)
    with connect(case) as db:
        if db.execute("SELECT 1 FROM imports WHERE sha256=?", (digest.hexdigest(),)).fetchone():
            raise ValueError("This exact file is already in the case.")
        import_id = db.execute("INSERT INTO imports(name,sha256,imported_at,timezone_offset,syslog_year) VALUES(?,?,?,?,?)", (path.name, digest.hexdigest(), datetime.now(timezone.utc).isoformat(), offset, year)).lastrowid
        count = rejected = undated = assumed_count = decode_warnings = 0
        batch = []
        def flush():
            db.executemany("INSERT INTO events(import_id,line,timestamp,host,user,src_ip,dst_ip,action,severity,message,failed,raw,provider,event_id,channel,record_id,decode_warning) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
            batch.clear()
        if progress and name.endswith((".evtx", ".etl")):
            progress(f"Decoding {path.name} with Windows; provider-dependent. Cancellation is available.")
        with closing(records(path, year, check, input_format, json_path)) as source:
            for n, row in source:
                check()
                if row is None:
                    rejected += 1
                    continue
                normalized, assumed = normalize(row, zone)
                count += 1
                undated += normalized["timestamp"] is None
                assumed_count += assumed
                decode_warnings += bool(normalized["decode_warning"])
                batch.append((import_id, n, *(normalized[k] for k in ("timestamp", "host", "user", "src_ip", "dst_ip", "action", "severity", "message", "failed")), json.dumps(row, ensure_ascii=False), *(normalized[k] for k in ("provider", "event_id", "channel", "record_id", "decode_warning"))))
                if len(batch) >= 2000:
                    flush()
                    if progress:
                        progress(f"{path.name}: {count:,} events; {rejected:,} rejected; {decode_warnings:,} decode warnings")
        flush()
        check()
        if not count:
            raise ValueError("No valid records found; import rolled back.")
        db.execute("UPDATE imports SET records=?,rejected=?,undated=?,assumed=?,decode_warnings=? WHERE id=?", (count, rejected, undated, assumed_count, decode_warnings, import_id))
    return {"records": count, "rejected": rejected, "undated": undated, "assumed": assumed_count, "decode_warnings": decode_warnings}


def filters(search="", ip="", start="", end="", event_id="", provider=""):
    parts, args = [], []
    if search:
        parts.append("(host LIKE ? ESCAPE '\\' OR user LIKE ? ESCAPE '\\' OR action LIKE ? ESCAPE '\\' OR message LIKE ? ESCAPE '\\' OR provider LIKE ? ESCAPE '\\' OR channel LIKE ? ESCAPE '\\')")
        pattern = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        args += [pattern] * 6
    for field, value in (("event_id", event_id), ("provider", provider)):
        if value:
            parts.append(field + "=?")
            args.append(str(value))
    if ip:
        address = clean_ip(ip)
        if not address:
            raise ValueError("Enter a valid IPv4 or IPv6 address.")
        parts.append("(src_ip=? OR dst_ip=?)")
        args += [address, address]
    bounds = []
    for value, operator in ((start, ">="), (end, "<=")):
        if value:
            stamp, _ = parse_time(value, timezone.utc)
            if not stamp:
                raise ValueError("Time filters require ISO dates/times, interpreted as UTC if no offset.")
            parts.append(f"timestamp {operator} ?")
            args.append(stamp)
            bounds.append(stamp)
    if len(bounds) == 2 and bounds[0] > bounds[1]:
        raise ValueError("Start time must not be after end time.")
    return (" WHERE " + " AND ".join(parts) if parts else ""), args


def query_events(case, limit=500, after=0, **kwargs):
    where, args = filters(**kwargs)
    where += (" AND " if where else " WHERE ") + "id>?"
    with connect(case) as db:
        return [dict(r) for r in db.execute("SELECT * FROM events" + where + " ORDER BY id LIMIT ?", [*args, after, min(max(limit, 1), 5000)])]


def summary(case):
    with connect(case) as db:
        totals = dict(db.execute("SELECT count(*) events, count(DISTINCT nullif(host,'')) hosts, min(timestamp) first, max(timestamp) last, sum(timestamp IS NULL) undated FROM events").fetchone())
        totals["imports"] = [dict(r) for r in db.execute("SELECT * FROM imports ORDER BY id")]
        totals["timeline"] = [dict(r) for r in db.execute("SELECT substr(timestamp,1,13) hour, count(*) count FROM events WHERE timestamp IS NOT NULL GROUP BY hour ORDER BY hour DESC LIMIT 48")][::-1]
        totals["ips"] = [dict(r) | {"scope": ip_scope(r["ip"])} for r in db.execute("SELECT ip,count(*) count FROM (SELECT src_ip ip FROM events WHERE src_ip!='' UNION ALL SELECT dst_ip ip FROM events WHERE dst_ip!='') GROUP BY ip ORDER BY count DESC,ip LIMIT 20")]
        return totals


def load_indicators(path):
    networks = []
    with open(path, encoding="utf-8-sig") as source:
        for n, line in enumerate(source, 1):
            value = line.split("#", 1)[0].strip()
            if not value:
                continue
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError as exc:
                raise ValueError(f"Invalid IP/CIDR indicator on line {n}") from exc
            if len(networks) > 10000:
                raise ValueError("Indicator list is limited to 10,000 entries.")
    return networks


SECURITY = "microsoft-windows-security-auditing"
# (rule, event IDs, accepted providers (lowercase), explanation). Provider must match exactly,
# so a generic CSV column named EventId never triggers a Windows rule.
WINDOWS_RULES = (
    ("LOG_CLEARED", ("1102",), (SECURITY, "microsoft-windows-eventlog"), "Security audit log cleared (1102). Confirm whether clearing was authorized."),
    ("LOG_CLEARED", ("104",), ("microsoft-windows-eventlog",), "Event log cleared (104). Confirm whether clearing was authorized."),
    ("NEW_SERVICE", ("7045",), ("service control manager",), "New service installed (7045). Review the service binary path and account."),
    ("NEW_SERVICE", ("4697",), (SECURITY,), "Service installed in the system (4697). Review the service binary path and account."),
    ("PRIV_GROUP_CHANGE", ("4728", "4732", "4756"), (SECURITY,), "Member added to a security-enabled group (4728/4732/4756). Check whether the group is privileged and the change approved."),
    ("ACCOUNT_CREATED", ("4720",), (SECURITY,), "User account created (4720). Confirm the account is expected."),
    ("SCHEDULED_TASK", ("4698",), (SECURITY,), "Scheduled task created (4698). Review the task action and author."),
)


def windows_findings(db):
    findings = []
    for rule, event_ids, providers, reason in WINDOWS_RULES:
        marks = ",".join("?" * len(event_ids))
        pmarks = ",".join("?" * len(providers))
        sql = (f"SELECT coalesce(nullif(host,''),'(unknown host)') entity, min(timestamp) first, max(timestamp) last, count(*) events, "
               f"count(*) metric, min(id) evidence_id, count(DISTINCT import_id) sources, group_concat(DISTINCT event_id) ids "
               f"FROM events WHERE event_id IN ({marks}) AND lower(provider) IN ({pmarks}) GROUP BY entity ORDER BY events DESC LIMIT 1000")
        for row in db.execute(sql, (*event_ids, *providers)):
            findings.append(dict(row) | {"rule": rule, "reason": reason, "pivot": {"event_id": row["ids"].split(",")[0], "search": "" if row["entity"] == "(unknown host)" else row["entity"]}})
    return findings


def analyze(case, indicators=(), failure_threshold=5, fanout_threshold=20, windows_rules=True):
    """Whole-case, UTC fixed five-minute buckets; not sliding windows. Windows rules are per-host event matches."""
    if failure_threshold < 2 or fanout_threshold < 2:
        raise ValueError("Thresholds must be at least two.")
    findings = []
    bucket = "CAST(strftime('%s',timestamp) AS INTEGER)/300"
    with connect(case) as db:
        for rule, condition, metric, threshold, label in (
            ("AUTH_BURST", "failed=1 AND src_ip!=''", "count(*)", failure_threshold, "authentication failure indicators"),
            ("DEST_FANOUT", "src_ip!='' AND dst_ip!=''", "count(DISTINCT dst_ip)", fanout_threshold, "distinct destination IPs"),
        ):
            sql = f"SELECT src_ip entity, min(timestamp) first, max(timestamp) last, count(*) events, {metric} metric, min(id) evidence_id, count(DISTINCT import_id) sources FROM events WHERE timestamp IS NOT NULL AND {condition} GROUP BY src_ip,{bucket} HAVING {metric}>=? ORDER BY metric DESC LIMIT 1001"
            rows = db.execute(sql, (threshold,)).fetchall()
            for row in rows[:1000]:
                findings.append(dict(row) | {"rule": rule, "reason": f"{row['metric']} {label} in a fixed 5-minute UTC bucket (threshold {threshold})."})
            if len(rows) > 1000:
                findings.append({"rule": "LIMIT", "entity": rule, "reason": "More than 1,000 groups matched; only the top 1,000 are shown."})
        if indicators:
            # Iterate distinct addresses without loading all events into RAM.
            hits = 0
            for row in db.execute("SELECT src_ip ip FROM events WHERE src_ip!='' UNION SELECT dst_ip FROM events WHERE dst_ip!=''"):
                addr = ipaddress.ip_address(row[0])
                if any(addr.version == network.version and addr in network for network in indicators):
                    hits += 1
                    if hits > 1000:
                        findings.append({"rule": "LIMIT", "entity": "LOCAL_IOC", "reason": "More than 1,000 addresses matched; only the first 1,000 are shown."})
                        break
                    detail = db.execute("SELECT min(timestamp) first,max(timestamp) last,count(*) events,min(id) evidence_id,count(DISTINCT import_id) sources FROM events WHERE src_ip=? OR dst_ip=?", (str(addr), str(addr))).fetchone()
                    findings.append(dict(detail) | {"rule": "LOCAL_IOC", "entity": str(addr), "metric": detail["events"], "reason": "Address matches the user-supplied local IP/CIDR list. List quality and relevance require validation."})
        if windows_rules:
            findings.extend(windows_findings(db))
    return findings


def add_annotation(case, event_ref, tag="", note=""):
    tag, note = (tag or "").strip(), (note or "").strip()
    if not tag and not note:
        raise ValueError("Enter a tag or a note.")
    if len(tag) > MAX_TAG or len(note) > MAX_NOTE:
        raise ValueError(f"Tags are limited to {MAX_TAG} characters and notes to {MAX_NOTE}.")
    with connect(case) as db:
        if not db.execute("SELECT 1 FROM events WHERE id=?", (int(event_ref),)).fetchone():
            raise ValueError(f"Event {event_ref} does not exist in this case.")
        cursor = db.execute("INSERT INTO annotations(event_ref,tag,note,created_at) VALUES(?,?,?,?)", (int(event_ref), tag, note, datetime.now(timezone.utc).isoformat(timespec="seconds")))
        return cursor.lastrowid


def list_annotations(case, event_ref=None):
    sql = ("SELECT a.id, a.event_ref, a.tag, a.note, a.created_at, e.timestamp, e.host, e.src_ip, e.dst_ip, e.action, e.event_id, e.import_id "
           "FROM annotations a JOIN events e ON e.id=a.event_ref")
    args = ()
    if event_ref is not None:
        sql += " WHERE a.event_ref=?"
        args = (int(event_ref),)
    with connect(case) as db:
        return [dict(r) for r in db.execute(sql + " ORDER BY e.timestamp IS NULL, e.timestamp, a.id", args)]


def delete_annotation(case, annotation_id):
    with connect(case) as db:
        if not db.execute("DELETE FROM annotations WHERE id=?", (int(annotation_id),)).rowcount:
            raise ValueError(f"Annotation {annotation_id} does not exist.")


def source_timeline(case, hours=48):
    """Per-source event counts for the latest populated UTC hours across the case."""
    with connect(case) as db:
        latest = [r[0] for r in db.execute("SELECT DISTINCT substr(timestamp,1,13) hour FROM events WHERE timestamp IS NOT NULL ORDER BY hour DESC LIMIT ?", (int(hours),))][::-1]
        if not latest:
            return {"hours": [], "sources": []}
        rows = db.execute("SELECT i.id, i.name, substr(e.timestamp,1,13) hour, count(*) count FROM events e JOIN imports i ON i.id=e.import_id "
                          "WHERE e.timestamp IS NOT NULL AND substr(e.timestamp,1,13)>=? GROUP BY i.id, hour", (latest[0],)).fetchall()
    sources = {}
    for row in rows:
        entry = sources.setdefault(row["id"], {"id": row["id"], "name": row["name"], "counts": {}})
        entry["counts"][row["hour"]] = row["count"]
    return {"hours": latest, "sources": [sources[k] for k in sorted(sources)]}
