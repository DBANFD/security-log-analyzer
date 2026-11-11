"""CEF, LEEF and W3C parsers. Source lines and vendor fields are retained."""
import csv
import re
from datetime import datetime


def warning_record(line, parser, error):
    return {"source_format": parser, "raw_line": line, "message": line,
            "decode_warning": f"{parser.upper()} parsing incomplete: {error}"}


def unescape(value, header=False):
    allowed = {"\\": "\\", "|": "|"} if header else {"\\": "\\", "=": "=", "n": "\n", "r": "\r"}
    return re.sub(r"\\(.)", lambda m: allowed.get(m[1], m[0]), value)


def split_header(text, count):
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for index, char in enumerate(text):
        if char == "|" and not escaped:
            parts.append(unescape("".join(current), True))
            current = []
            if len(parts) == count:
                return parts, text[index + 1:]
        else:
            current.append(char)
        escaped = char == "\\" and not escaped
    raise ValueError(f"Expected {count} pipe-delimited header fields")


def put(fields, key, value, warnings):
    if key in fields:
        warnings.append(f"Duplicate attribute {key}; first value used, original line retained")
    else:
        fields[key] = value


def device_time(value, time_format=""):
    """Explicit ISO/epoch or a small documented set of Java-style date tokens."""
    value = str(value or "")
    if not value:
        return "", ""
    if re.fullmatch(r"\d{10}(?:\.\d+)?|\d{13}", value):
        return value, ""
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value, ""
    except ValueError:
        pass
    mappings = {
        "yyyy-MM-dd HH:mm:ss": "%Y-%m-%d %H:%M:%S",
        "yyyy-MM-dd HH:mm:ss.SSS": "%Y-%m-%d %H:%M:%S.%f",
        "yyyy-MM-dd HH:mm:ss Z": "%Y-%m-%d %H:%M:%S %z",
        "yyyy-MM-dd'T'HH:mm:ssZ": "%Y-%m-%dT%H:%M:%S%z",
        "yyyy-MM-dd'T'HH:mm:ss.SSSZ": "%Y-%m-%dT%H:%M:%S.%f%z",
        "yyyy-MM-dd'T'HH:mm:ssXXX": "%Y-%m-%dT%H:%M:%S%z",
        "yyyy-MM-dd'T'HH:mm:ss.SSSXXX": "%Y-%m-%dT%H:%M:%S.%f%z",
        "MMM dd yyyy HH:mm:ss": "%m %d %Y %H:%M:%S",
        "MMM dd yyyy HH:mm:ss.SSS": "%m %d %Y %H:%M:%S.%f",
        "MMM dd yyyy HH:mm:ss z": "%m %d %Y %H:%M:%S %z",
    }
    if not time_format:
        time_format = "MMM dd yyyy HH:mm:ss.SSS" if "." in value else "MMM dd yyyy HH:mm:ss"
    format_string = mappings.get(time_format)
    if format_string:
        adjusted = value
        if time_format.startswith("MMM"):
            months = {name: str(i) for i, name in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
            first, separator, rest = adjusted.partition(" ")
            adjusted = months.get(first, first) + separator + rest
        adjusted = adjusted.replace("GMT", "").replace("UTC", "+0000").strip()
        try:
            return datetime.strptime(adjusted, format_string).isoformat(), ""
        except ValueError:
            pass
    return value, "Unsupported or invalid device timestamp; original value retained (no time guessed)"


def common_record(parser, line, header, attrs, inherited, warnings):
    lower = {k.lower(): v for k, v in attrs.items()}
    def pick(*keys):
        return next((lower[k] for k in keys if lower.get(k) not in (None, "", "-")), "")
    timestamp, problem = device_time(pick("devtime", "rt", "end", "start"), pick("devtimeformat"))
    if problem:
        warnings.append(problem)
    return {
        "source_format": parser, "raw_line": line, "header": header, "attributes": attrs,
        "timestamp": timestamp or inherited.get("timestamp", ""),
        "host": pick("dvchost", "dhost", "shost") or inherited.get("host", ""),
        "src_ip": pick("src", "srcip", "sourceip"), "dst_ip": pick("dst", "dstip", "destinationip"),
        "user": pick("suser", "usrname", "username", "duser"),
        "provider": header["vendor"] + "/" + header["product"],
        "event_id": header["event_id"], "action": pick("act", "action", "cat") or header["event_id"],
        "severity": pick("sev") or header.get("severity", ""),
        "message": pick("msg", "message") or header.get("name", "") or line,
        "decode_warning": "; ".join(warnings),
    }


def parse_cef(line, inherited=None):
    match = re.search(r"(?<!\S)CEF:", line)
    if not match:
        raise ValueError("Missing CEF header")
    parts, extension = split_header(line[match.start():], 7)
    if parts[0] not in ("CEF:0", "CEF:1"):
        raise ValueError("Only CEF versions 0 and 1 are supported")
    header = dict(zip(("version", "vendor", "product", "product_version", "event_id", "name", "severity"), parts))
    fields: dict = {}
    warnings: list[str] = []
    matches = list(re.finditer(r"(?:^|[ \t]+)([A-Za-z][A-Za-z0-9_.-]*)=", extension))
    if extension.strip() and (not matches or extension[:matches[0].start()].strip()):
        warnings.append("Unparsed CEF extension text")
    for i, item in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(extension)
        put(fields, item[1], unescape(extension[item.end():end].rstrip()), warnings)
    return common_record("cef", line, header, fields, inherited or {}, warnings)


def parse_leef(line, inherited=None):
    match = re.search(r"(?<!\S)LEEF:", line)
    if not match:
        raise ValueError("Missing LEEF header")
    text = line[match.start():]
    if not text.startswith(("LEEF:1.0|", "LEEF:2.0|")):
        raise ValueError("Only LEEF 1.0 and 2.0 are supported")
    parts, extension = split_header(text, 6 if text.startswith("LEEF:2.0|") else 5)
    header = dict(zip(("version", "vendor", "product", "product_version", "event_id", "delimiter"), parts))
    delimiter = header.get("delimiter", "\t")
    if re.fullmatch(r"(?:0[xX]|[xX])[0-9a-fA-F]{2,4}", delimiter):
        delimiter = chr(int(delimiter.lower().split("x", 1)[1], 16))
    if len(delimiter) != 1 or delimiter in ("=", "\r", "\n", "\x00"):
        raise ValueError("LEEF 2.0 requires a single valid delimiter or hex character code")
    fields: dict = {}
    warnings: list[str] = []
    for item in extension.split(delimiter):
        if not item:
            continue
        key, separator, value = item.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", key):
            warnings.append("Malformed LEEF attribute retained in original line")
            continue
        # LEEF attributes use their delimiter, not CEF escaping or whitespace.
        put(fields, key, value, warnings)
    return common_record("leef", line, header, fields, inherited or {}, warnings)


class W3CParser:
    def __init__(self):
        self.fields = None

    def parse(self, line):
        if line.startswith("#Fields:"):
            fields = line.partition(":")[2].split()
            if not fields or len(fields) != len({field.lower() for field in fields}):
                self.fields = None
                return warning_record(line, "w3c", "Missing or duplicate #Fields names")
            self.fields = fields
            return None
        if line.startswith("#"):
            return None
        if not self.fields:
            return warning_record(line, "w3c", "No valid #Fields header; cannot map values")
        try:
            values = next(csv.reader([line.strip()], delimiter=" ", skipinitialspace=True, strict=True))
        except csv.Error as exc:
            return warning_record(line, "w3c", str(exc))
        if len(values) != len(self.fields):
            return warning_record(line, "w3c", "Field count does not match current #Fields header")
        original = dict(zip(self.fields, values))
        fields = {k.lower(): v if v != "-" else "" for k, v in original.items()}
        date, time = fields.get("date"), fields.get("time")
        timestamp = f"{date}T{time}Z" if date and time else ""
        status = fields.get("sc-status", "")
        severity = "error" if status.isdigit() and int(status) >= 500 else "warning" if status.startswith("4") else "info"
        uri = fields.get("cs-uri-stem", "")
        if fields.get("cs-uri-query"):
            uri += "?" + fields["cs-uri-query"]
        message = f"{fields.get('cs-method', '')} {uri} status={status} substatus={fields.get('sc-substatus', '')} time-taken={fields.get('time-taken', '')} user-agent={fields.get('cs(user-agent)', '')}"
        return {"source_format": "w3c", "raw_line": line, "w3c_fields": original,
                "timestamp": timestamp, "host": fields.get("s-computername") or fields.get("s-sitename", ""),
                "src_ip": fields.get("c-ip", ""), "dst_ip": fields.get("s-ip", ""),
                "user": fields.get("cs-username", ""), "provider": "IIS/W3C",
                "action": fields.get("cs-method", ""), "severity": severity, "message": message,
                "decode_warning": "Missing date/time; no timestamp inferred" if not timestamp else ""}
