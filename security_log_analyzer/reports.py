"""Local exports with HTML escaping and spreadsheet formula neutralization."""
import csv
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from .core import connect, filters, summary, list_annotations, source_timeline

LIMITS = (
    "Triage indicators are not proof of compromise. Public IP addresses are not inherently suspicious. "
    "Rules use fixed five-minute UTC buckets, not sliding windows; activity crossing a bucket boundary can be missed. "
    "Events without usable timestamps are excluded from time-based rules. Correlation links matching source IPs across "
    "imports and may combine unrelated clients behind NAT. No geolocation, reputation service, or network lookup is used. "
    "Parse/decode warnings flag incomplete or ambiguous parsing, including Windows message rendering; inspect source quality. "
    "Windows rules match single events by event ID and exact provider per host; they flag activity to review, not malicious intent. "
    "Analyst tags and notes are local opinions recorded in the case, not source evidence. "
    "The report covers the whole case, independently of the event-view filters."
)


def check_output(case, path):
    if Path(case).resolve() == Path(path).resolve():
        raise ValueError("Export cannot overwrite the case database.")


def export_csv(case, path, **kwargs):
    check_output(case, path)
    where, args = filters(**kwargs)
    columns = ["id", "import_id", "line", "timestamp", "host", "user", "src_ip", "dst_ip", "action", "severity", "message", "provider", "event_id", "channel", "record_id", "decode_warning"]
    count = 0
    with connect(case) as db, open(path, "w", encoding="utf-8-sig", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(columns)
        for row in db.execute("SELECT " + ",".join(columns) + " FROM events" + where + " ORDER BY id", args):
            safe = []
            for value in row:
                text = "" if value is None else str(value)
                if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
                    text = "'" + text
                safe.append(text)
            writer.writerow(safe)
            count += 1
    return count


def export_report(case, path, findings, configuration=None):
    check_output(case, path)
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "scope": "whole case", "summary": summary(case), "rules": configuration or {}, "findings": findings,
              "annotations": list_annotations(case), "source_timeline": source_timeline(case), "limitations": LIMITS}
    path = Path(path)
    if path.suffix.lower() == ".json":
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        return
    def esc(value):
        return html.escape(str(value if value is not None else ""))
    def table(rows, columns):
        return "<table><thead><tr>" + "".join(f"<th>{esc(c)}</th>" for c in columns) + "</tr></thead><tbody>" + "".join("<tr>" + "".join(f"<td>{esc(r.get(c, ''))}</td>" for c in columns) + "</tr>" for r in rows) + "</tbody></table>"
    stats = report["summary"]
    document = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Security Log Analyzer report</title>
<style>body{font:15px system-ui,sans-serif;background:#101423;color:#e9edf7;max-width:1200px;margin:40px auto;padding:24px}h1,h2{color:#c1b4ff}p{line-height:1.6}table{width:100%;border-collapse:collapse;margin:20px 0;font-size:13px}td,th{text-align:left;border-bottom:1px solid #39415b;padding:10px;overflow-wrap:anywhere}th{color:#b6e9de}.note{padding:18px;background:#20283d;border-radius:8px}@media print{body{background:white;color:black}h1,h2,th{color:black}table{font-size:10px}.note{background:#eee}}</style>
<h1>Security Log Analyzer</h1>"""
    document += f"<p>Whole-case triage report · Generated {esc(report['generated_at'])}</p>"
    document += f"<p>{stats['events']:,} events · {stats['hosts']:,} hosts · {len(stats['imports'])} source files · {stats['undated'] or 0:,} undated events</p>"
    document += f"<p>UTC range: {esc(stats['first'])} to {esc(stats['last'])}</p><p class='note'>{esc(LIMITS)}</p>"
    document += "<h2>Rule configuration</h2><pre>" + esc(json.dumps(report["rules"], indent=2)) + "</pre>"
    document += "<h2>Findings</h2>" + (table(findings, ["rule", "entity", "events", "first", "last", "sources", "evidence_id", "reason"]) if findings else "<p>No configured rules matched. This does not establish absence of malicious activity.</p>")
    document += "<h2>Source provenance</h2>" + table(stats["imports"], ["id", "name", "sha256", "records", "rejected", "undated", "assumed", "decode_warnings", "timezone_offset", "syslog_year"])
    document += "<h2>Top IP observations</h2>" + table(stats["ips"], ["ip", "count", "scope"])
    document += "<h2>Analyst notes</h2>" + (table(report["annotations"], ["event_ref", "timestamp", "host", "src_ip", "dst_ip", "event_id", "tag", "note", "created_at"]) if report["annotations"] else "<p>No tags or notes recorded.</p>")
    document += "<h2>Timeline: latest 48 populated UTC hours</h2>" + table(stats["timeline"], ["hour", "count"])
    timeline = report["source_timeline"]
    if timeline["sources"]:
        rows = [{"hour": hour.replace("T", " ") + ":00", **{f"#{s['id']} {s['name']}": s["counts"].get(hour, "") for s in timeline["sources"]}} for hour in timeline["hours"]]
        document += "<h2>Timeline by source</h2>" + table(rows, ["hour"] + [f"#{s['id']} {s['name']}" for s in timeline["sources"]])
    document += "</html>"
    path.write_text(document, encoding="utf-8")
