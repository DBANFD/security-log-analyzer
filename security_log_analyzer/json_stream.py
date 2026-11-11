"""Bounded streaming JSON selection and conservative nested-field mapping."""
import json
import re

MAX_EVENT = 1024 * 1024
MAX_DEPTH = 64
AUTO_PATHS = {(), ("events",), ("records",), ("value",), ("items",), ("results",), ("data",), ("hits", "hits")}
AUTO_PATHS.update({("data", key) for key in ("events", "records", "items", "results", "value")})


def pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key {key!r}; ambiguous record refused")
        result[key] = value
    return result


def strict_loads(text):
    return json.loads(text, object_pairs_hook=pairs_unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Non-standard JSON number: " + value)))


def pointer_parts(pointer):
    if pointer == "$":
        return ()
    if not pointer.startswith("/"):
        raise ValueError("JSON path must be a JSON Pointer such as /data/events, or $ for the root")
    if re.search(r"~(?![01])", pointer):
        raise ValueError("JSON Pointer escape must be ~0 or ~1")
    return tuple(part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/"))


def pointer_text(parts):
    return "/" + "/".join(str(p).replace("~", "~0").replace("/", "~1") for p in parts) if parts else "$"


def nested_record(original, path="$"):
    # Existing Windows decoder JSON round trips keep their explicit metadata.
    if original.get("windows_event") is True:
        return original
    base = original.get("_source") if isinstance(original.get("_source"), dict) else original
    flat: dict = {}
    leaves: dict = {}
    def flatten(value, parts=()):
        if len(parts) > MAX_DEPTH:
            raise ValueError("JSON nesting exceeds 64 levels")
        if isinstance(value, dict):
            for key, child in value.items():
                flatten(child, parts + (key,))
        elif not isinstance(value, (list, tuple)) and value is not None and str(value).strip():
            canonical = tuple(re.sub(r"[ _-]", "", p.lower()) for p in parts)
            flat[canonical] = value
            leaves.setdefault(canonical[-1], []).append((canonical, value))
    flatten(base)
    mappings = {
        "timestamp": ("timestamp", "timegenerated", "@timestamp", "datetime", "eventtime", "time", "event.created", "event.start", "properties.timegenerated", "properties.timestamp"),
        "host": ("devicename", "computer", "hostname", "host", "dvc", "devname", "host.name", "device.name", "agent.hostname", "properties.devicename"),
        "user": ("accountupn", "accountname", "userprincipalname", "targetusername", "user", "username", "srcuser", "user.name", "user.email", "user.id"),
        "src_ip": ("sourceip", "sourceipaddress", "srcip", "src", "ipaddress", "localip", "source.ip", "client.ip", "network.source.ip"),
        "dst_ip": ("destinationip", "destinationipaddress", "dstip", "dst", "remoteip", "destination.ip", "server.ip", "network.destination.ip"),
        "action": ("actiontype", "activity", "action", "eventid", "eventname", "event.action", "event.code"),
        "severity": ("severity", "loglevel", "level", "eventseverity", "log.level", "event.severity"),
        "message": ("message", "syslogmessage", "description", "msg", "commandline", "processcommandline", "event.original", "process.commandline"),
        "provider": ("provider", "providername", "event.provider", "winlog.providername", "log.logger"),
        "event_id": ("eventid", "event.code", "winlog.eventid"),
        "channel": ("channel", "logname", "winlog.channel"),
        "record_id": ("recordid", "eventrecordid", "winlog.recordid"),
        "decode_warning": ("decodewarning",),
    }
    result = {"source_format": "json", "json_path": path, "original": original}
    warnings = []
    for target, aliases in mappings.items():
        found = False
        for alias in aliases:
            parts = tuple(alias.split("."))
            # Literal dotted keys (ECS exports) are also explicit mappings.
            for key in ((alias,), parts):
                if key in flat:
                    result[target] = flat[key]
                    found = True
                    break
            if found:
                break
        if found:
            continue
        candidates = []
        for alias in aliases:
            if "." not in alias:
                candidates.extend(leaves.get(alias, []))
        unique = {parts: value for parts, value in candidates}
        if len(unique) == 1:
            result[target] = next(iter(unique.values()))
        elif len(unique) > 1:
            warnings.append(f"Ambiguous nested {target}; left blank")
    if not any(result.get(key) for key in mappings if key != "decode_warning"):
        warnings.append("No recognized JSON event fields; original object retained")
    if warnings:
        result["decode_warning"] = "; ".join(filter(None, (str(result.get("decode_warning", "")), *warnings)))
    if ("date",) in flat and ("time",) in flat:
        result["date"], result["time"] = flat[("date",)], flat[("time",)]
    return result


class JSONStream:
    def __init__(self, stream, check):
        self.stream, self.check = stream, check
        self.buffer, self.index = "", 0
        self.selected = []

    def peek(self):
        if self.index >= len(self.buffer):
            self.check()
            self.buffer = self.stream.read(65536)
            self.index = 0
        return self.buffer[self.index:self.index + 1]

    def take(self):
        value = self.peek()
        self.index += bool(value)
        return value

    def space(self):
        while self.peek() and self.peek() in " \r\n\t":
            self.take()

    def expect(self, char):
        self.space()
        if self.take() != char:
            raise ValueError(f"Invalid JSON: expected {char!r}")

    def value(self):
        """Capture one bounded JSON value, then validate it with stdlib JSON."""
        self.space()
        first = self.peek()
        if not first:
            raise ValueError("Unexpected end of JSON")
        output: list[str] = []
        stack: list[str] = []
        quoted = escaped = False
        container = first in "[{"
        string = first == '"'
        while self.peek():
            char = self.peek()
            if output and not quoted and not stack and not container and not string and char in " \t\r\n,]}":
                break
            char = self.take()
            output.append(char)
            if len(output) > MAX_EVENT:
                raise ValueError("JSON value exceeds 1 MiB; file rolled back")
            if quoted:
                if char == '"' and not escaped:
                    quoted = False
                    if string and not stack:
                        break
                escaped = char == "\\" and not escaped
                continue
            if char == '"':
                quoted, escaped = True, False
            elif char in "[{":
                stack.append(char)
                if len(stack) > MAX_DEPTH:
                    raise ValueError("JSON nesting exceeds 64 levels")
            elif char in "]}":
                if not stack or stack.pop() != ("]" == char and "[" or "{"):
                    raise ValueError("Mismatched JSON delimiter")
                if not stack:
                    break
        return strict_loads("".join(output))

    def walk(self, targets, explicit, path=(), depth=0):
        if depth > MAX_DEPTH:
            raise ValueError("JSON nesting exceeds 64 levels")
        self.space()
        token = self.peek()
        match_path = path if explicit else tuple(part.lower() for part in path)
        if match_path in targets and (token == "[" or explicit):
            self.selected.append(path)
            if len(self.selected) > 1:
                raise ValueError("Multiple JSON event arrays found; select one using JSON path")
            if token != "[":
                value = self.value()
                if not isinstance(value, dict):
                    raise ValueError("Selected JSON path must contain an object or array of objects")
                yield nested_record(value, pointer_text(path))
                return
            self.expect("[")
            self.space()
            index = 0
            if self.peek() == "]":
                self.take()
                return
            while True:
                value = self.value()
                yield nested_record(value, pointer_text(path + (str(index),))) if isinstance(value, dict) else None
                index += 1
                self.space()
                char = self.take()
                if char == "]":
                    return
                if char != ",":
                    raise ValueError("JSON array requires comma or closing bracket")
        elif token == "{":
            self.take()
            seen = set()
            self.space()
            if self.peek() == "}":
                self.take()
                return
            while True:
                key = self.value()
                if not isinstance(key, str) or key in seen:
                    raise ValueError("Invalid or duplicate JSON object key")
                seen.add(key)
                if len(seen) > 10000:
                    raise ValueError("JSON object has more than 10,000 keys")
                self.expect(":")
                yield from self.walk(targets, explicit, path + (key,), depth + 1)
                self.space()
                char = self.take()
                if char == "}":
                    return
                if char != ",":
                    raise ValueError("JSON object requires comma or closing brace")
        elif token == "[":
            self.take()
            self.space()
            if self.peek() == "]":
                self.take()
                return
            index = 0
            while True:
                yield from self.walk(targets, explicit, path + (str(index),), depth + 1)
                index += 1
                self.space()
                char = self.take()
                if char == "]":
                    return
                if char != ",":
                    raise ValueError("JSON array requires comma or closing bracket")
        else:
            self.value()


def json_records(stream, pointer="", check=lambda: None):
    targets = {pointer_parts(pointer)} if pointer else AUTO_PATHS
    reader = JSONStream(stream, check)
    for n, record in enumerate(reader.walk(targets, bool(pointer)), 1):
        yield n, record
    reader.space()
    if reader.peek():
        raise ValueError("Unexpected trailing content after JSON document")
    if not reader.selected:
        if pointer:
            raise ValueError("JSON path not found: " + pointer)
        stream.seek(0)
        text = stream.read(MAX_EVENT + 1)
        if len(text) > MAX_EVENT:
            raise ValueError("No recognized event array; supply JSON path (single objects limited to 1 MiB)")
        value = strict_loads(text)
        if not isinstance(value, dict):
            raise ValueError("JSON requires an object or event array")
        yield 1, nested_record(value)
