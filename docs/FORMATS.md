# Formats and normalization

Column matching is case-insensitive and ignores spaces, underscores, and hyphens. If several aliases are populated, the first in the list wins. All original fields are retained in the record JSON.

| Normalized field | Aliases, in precedence order |
| --- | --- |
| timestamp | Timestamp, TimeGenerated, DateTime, EventTime, @timestamp, Time |
| host | DeviceName, Computer, Hostname, Host, Dvc, DevName |
| user | AccountUpn, AccountName, UserPrincipalName, TargetUserName, User, Username, SrcUser |
| source IP | SourceIP, SourceIPAddress, SrcIP, Src, IPAddress, LocalIP |
| destination IP | DestinationIP, DestinationIPAddress, DstIP, Dst, RemoteIP |
| action | ActionType, Activity, Action, EventID, EventName |
| severity | Severity, LogLevel, Level, EventSeverity |
| message | Message, SyslogMessage, Description, Msg, CommandLine, ProcessCommandLine |

`LocalIP`/`RemoteIP` are normalized as source/destination for convenience. This does not establish network direction; inbound endpoint events may need interpretation from original fields. Unknown IP values are normalized to blank, while the raw field remains available. IP:port strings are not treated as IPs. IPv4-mapped IPv6 addresses are canonicalized to IPv4.

Separate `date` and `time` fields are joined and take precedence over other timestamps. Supported dates are ISO 8601 and Unix seconds (10 digits) or milliseconds (13 digits). Naive dates use a user-supplied fixed offset. The app does not infer daylight-saving time or ambiguous regional date formats. Split files spanning offset changes, or normalize timestamps before import. Unknown/unparseable timestamps are retained as undated records.

Legacy Syslog lacks a year. It remains undated unless a year is explicitly supplied. Do not assign one year to a file spanning New Year without splitting it. ISO timestamp Syslog uses the year/offset in the line. Syslog parsing retains application fields as message text; it is not a complete implementation of every structured-data or vendor extension.

Firewall parsing recognizes unquoted values or double-quoted `key=value` pairs, such as:

```text
date=2026-01-15 time=10:02:00 devname="demo-fw" srcip=10.10.0.25 dstip=192.0.2.10 action=deny msg="Synthetic event"
```

CSV and JSONL records with unrecognized fields are retained, but their normalized fields may be empty. Missing/extra CSV values and invalid JSONL objects are counted as rejected records. Invalid UTF-8, malformed CSV parser errors, and fatal I/O errors roll back that entire file. CSV with duplicate headers is refused. UTF-16 exports must be converted to UTF-8 first. No encoding is silently guessed.

Windows EVTX and ETL files are supported on Windows, and Windows Event XML on all platforms. See [Windows event formats](WINDOWS-EVENTS.md). `.tsv` uses a tab delimiter with the same header/field rules as CSV. Version 0.3 adds CEF/LEEF and IIS/W3C detection in `.log`/`.txt`/`.syslog`, dedicated `.cef`/`.leef`/`.w3c` extensions, and nested JSON/arrays. A multiline stack trace is still stored as separate lines unless converted to a supported structured format.

See [Structured logs](STRUCTURED-LOGS.md) for CEF escaping, LEEF delimiters, W3C headers, JSON container selection, mappings, and error behavior. Dedicated parsers are schema-aware; vendor-specific custom attributes remain available as evidence but are not all mapped into normalized fields.

PCAP/PCAPNG, legacy EVT, XLSX, ZIP bundles, arbitrary vendor-specific binary formats, and live product APIs remain outside scope.
