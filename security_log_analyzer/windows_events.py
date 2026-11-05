"""Windows file decoder. Only the bundled code is executed; paths stay data."""
import base64
import json
import os
import queue
import subprocess
import tempfile
import threading
from pathlib import Path
from xml.etree import ElementTree as ET

# EventLogReader opens a literal file path and reads forward, as required by ETL.
# No script file, execution-policy change, profile, elevation, or shell interpolation.
DECODER = r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$reader = $null
try {
    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($env:SLA_EVENT_PATH, [System.Diagnostics.Eventing.Reader.PathType]::FilePath)
    $query.ReverseDirection = $false
    $query.TolerateQueryErrors = $false
    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
    while ($null -ne ($event = $reader.ReadEvent())) {
        try {
            $warnings = New-Object System.Collections.Generic.List[string]
            $xml = ''
            $message = ''
            try { $xml = $event.ToXml() } catch { $warnings.Add('Event XML unavailable: ' + $_.Exception.Message) }
            try { $message = $event.FormatDescription() } catch { $warnings.Add('Message unavailable: ' + $_.Exception.Message) }
            if ([string]::IsNullOrWhiteSpace($message) -and $warnings.Count -eq 0) { $warnings.Add('No rendered message; provider resources may be missing.') }
            $stamp = ''
            if ($null -ne $event.TimeCreated) { $stamp = $event.TimeCreated.ToUniversalTime().ToString('o') }
            $data = [ordered]@{
                kind='event'; xml=$xml; message=$message; timestamp=$stamp
                provider=$event.ProviderName; provider_guid=[string]$event.ProviderId
                event_id=$event.Id; channel=$event.LogName; record_id=$event.RecordId
                host=$event.MachineName; severity=$event.Level; process_id=$event.ProcessId
                thread_id=$event.ThreadId; warnings=@($warnings.ToArray())
            }
            if (-not $xml) {
                try { $data['unrendered_properties'] = @($event.Properties | ForEach-Object { [string]$_.Value }) }
                catch { $warnings.Add('Payload properties unavailable.'); $data['warnings'] = @($warnings.ToArray()) }
            }
            [Console]::Out.WriteLine(($data | ConvertTo-Json -Depth 8 -Compress))
        } finally { $event.Dispose() }
    }
    [Console]::Out.WriteLine('{"kind":"complete"}')
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
} finally {
    if ($null -ne $reader) { $reader.Dispose() }
}
'''


def local_name(tag):
    return tag.rsplit("}", 1)[-1]


def event_xml_record(xml):
    if "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
        raise ValueError("XML DTDs and entity declarations are not supported.")
    root = ET.fromstring(xml)
    if local_name(root.tag) != "Event":
        raise ValueError("Expected Windows Event XML.")
    children = {local_name(c.tag): c for c in root}
    system = children.get("System")
    if system is None:
        raise ValueError("Windows Event XML requires System metadata.")
    fields = {local_name(c.tag): c for c in system}
    def value(name):
        element = fields.get(name)
        return element.text or "" if element is not None else ""
    def attribute(name, key):
        element = fields.get(name)
        return element.get(key, "") if element is not None else ""
    record = {"timestamp": attribute("TimeCreated", "SystemTime"), "host": value("Computer"),
              "event_id": value("EventID"), "provider": attribute("Provider", "Name") or attribute("Provider", "Guid"),
              "provider_guid": attribute("Provider", "Guid"), "channel": value("Channel"),
              "record_id": value("EventRecordID"), "severity": value("Level"),
              "process_id": attribute("Execution", "ProcessID"), "thread_id": attribute("Execution", "ThreadID"),
              "user_sid": attribute("Security", "UserID"), "event_xml": xml, "windows_event": True}
    payload = {}
    for section_name in ("EventData", "UserData", "Data"):
        section = children.get(section_name)
        if section is not None:
            for i, element in enumerate(section.iter()):
                if (element is section and section_name != "Data") or len(element):
                    continue
                key = element.get("Name") or local_name(element.tag)
                if key in payload:
                    key += f"_{i}"
                payload[key] = element.text or ""
    record["event_data"] = payload
    lowered = {k.lower(): v for k, v in payload.items()}
    # Payload cannot overwrite authoritative System metadata.
    for target, aliases in {
        "src_ip": ("sourceip", "sourceipaddress", "ipaddress", "clientaddress"),
        "dst_ip": ("destinationip", "destinationipaddress"),
        "user": ("targetusername", "subjectusername", "user", "username"),
    }.items():
        record[target] = next((lowered[k] for k in aliases if lowered.get(k) and lowered[k] != "-"), "")
    rendered = children.get("RenderingInfo")
    message = next((c.text or "" for c in rendered if local_name(c.tag) == "Message"), "") if rendered is not None else ""
    record["message"] = message or " | ".join(f"{key}={value}" for key, value in payload.items())
    record["action"] = record["event_id"]
    return record


def decode_record(data):
    warnings = list(data.get("warnings") or [])
    xml = data.get("xml") or ""
    try:
        record = event_xml_record(xml) if xml else {}
    except (ET.ParseError, ValueError) as exc:
        record = {"event_xml": xml}
        warnings.append("XML normalization failed: " + str(exc))
    for key in ("timestamp", "host", "provider", "provider_guid", "event_id", "channel", "record_id", "severity", "process_id", "thread_id"):
        if data.get(key) is not None and str(data[key]):
            record[key] = data[key]
    record["windows_event"] = True
    record["action"] = str(record.get("event_id", ""))
    if data.get("message"):
        record["message"] = data["message"]
    record.setdefault("message", "")
    record["decode_warning"] = "; ".join(warnings)
    if "unrendered_properties" in data:
        record["unrendered_properties"] = data["unrendered_properties"]
    return record


def windows_records(path, check=lambda: None):
    if os.name != "nt":
        raise ValueError("EVTX/ETL decoding requires Windows. Export Windows Event XML on Windows for cross-platform import.")
    if Path(path).suffix.lower() == ".etl":
        yield from etl_records(path, check)
        return
    executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    if not executable.is_file():
        raise ValueError("Windows PowerShell is required for EVTX/ETL decoding.")
    env = os.environ.copy()
    env["SLA_EVENT_PATH"] = str(Path(path).resolve())
    command = [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-EncodedCommand", base64.b64encode(DECODER.encode("utf-16-le")).decode("ascii")]
    messages = queue.Queue(maxsize=8)
    stop = threading.Event()
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors, env=env, creationflags=subprocess.CREATE_NO_WINDOW)
        def send(item):
            while not stop.is_set():
                try:
                    messages.put(item, timeout=.1)
                    return
                except queue.Full:
                    pass
        def read():
            try:
                while True:
                    line = process.stdout.readline(8 * 1024 * 1024 + 1)
                    if not line:
                        break
                    if len(line) > 8 * 1024 * 1024:
                        while line and not line.endswith(b"\n"):
                            line = process.stdout.readline(65536)
                        send(("oversize", None))
                    else:
                        send(("line", line))
            except Exception as exc:
                send(("error", str(exc)))
            finally:
                send(("eof", None))
        worker = threading.Thread(target=read, daemon=True)
        worker.start()
        complete = False
        n = 0
        try:
            while True:
                check()
                try:
                    kind, line = messages.get(timeout=.1)
                except queue.Empty:
                    continue
                if kind == "eof":
                    break
                if kind == "error":
                    raise ValueError("Windows decoder pipe failed: " + line)
                if kind == "oversize":
                    n += 1
                    yield n, None
                    continue
                data = json.loads(line.decode("utf-8-sig"))
                if data.get("kind") == "complete":
                    complete = True
                elif data.get("kind") == "event" and not complete:
                    n += 1
                    yield n, decode_record(data)
                else:
                    raise ValueError("Unexpected Windows decoder output.")
            while process.poll() is None:
                check()
                stop.wait(.1)
            if process.returncode or not complete:
                errors.seek(0)
                detail = errors.read(8192).decode("utf-8", errors="replace").strip()
                raise ValueError("Windows could not read the complete event file; import rolled back. " + detail)
        finally:
            stop.set()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            worker.join(timeout=5)
            process.stdout.close()


def etl_records(path, check=lambda: None):
    """Tracerpt handles ETW formats that EventLogReader cannot open."""
    executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/tracerpt.exe"
    if not executable.is_file():
        raise ValueError("Windows tracerpt.exe is required for ETL decoding.")
    with tempfile.TemporaryDirectory(prefix="sla-etl-") as folder, tempfile.TemporaryFile() as output:
        converted = Path(folder) / "events.evtx"
        # EVTX preserves native UTC timestamps; tracerpt's XML offset rendering
        # can differ from the native event time on some Windows versions.
        command = [str(executable), str(Path(path).resolve()), "-o", str(converted), "-of", "EVTX", "-lr", "-y"]
        process = subprocess.Popen(command, stdout=output, stderr=output, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            while process.poll() is None:
                check()
                threading.Event().wait(.1)
            check()
            if process.returncode or not converted.is_file():
                output.seek(0)
                detail = output.read(8192).decode("utf-8", errors="replace").strip()
                raise ValueError("Windows tracerpt could not decode this ETL; import rolled back. " + detail)
            from contextlib import closing
            with closing(windows_records(converted, check)) as source:
                for n, record in source:
                    if record is not None:
                        record["decoder"] = "Windows tracerpt -lr"
                        note = "ETL best-effort conversion: verify provider payload completeness."
                        record["decode_warning"] = "; ".join(filter(None, (record.get("decode_warning"), note)))
                    yield n, record
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def xml_records(stream, check=lambda: None):
    """Read Event/Events XML without retaining the entire document."""
    class SafeReader:
        tail = b""
        def read(self, size):
            check()
            data = stream.read(min(size, 65536))
            probe = (self.tail + data.replace(b"\x00", b"")).upper()
            if b"<!DOCTYPE" in probe or b"<!ENTITY" in probe:
                raise ValueError("XML DTDs and entity declarations are not supported.")
            self.tail = probe[-16:]
            return data
    root = None
    n = 0
    depth = 0
    for event, element in ET.iterparse(SafeReader(), events=("start", "end")):
        if event == "start":
            depth += 1
        if root is None:
            root = element
            if local_name(root.tag) not in ("Event", "Events"):
                raise ValueError("XML must contain Windows Event or Events, not arbitrary XML.")
        if event == "end" and local_name(element.tag) == "Event" and (element is root or depth == 2):
            n += 1
            xml = ET.tostring(element, encoding="unicode")
            if len(xml) > 1024 * 1024:
                yield n, None
            else:
                yield n, event_xml_record(xml)
            element.clear()
            if root is not element:
                root.clear()
        if event == "end":
            depth -= 1
