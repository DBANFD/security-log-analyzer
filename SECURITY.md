# Security and privacy

The runtime uses local files, SQLite, and Tk. It contains no HTTP client, telemetry, update checker, web server, cloud connector, shell execution of log content, or external UI assets. Input text is parsed as data. SQL values are parameterized; HTML is escaped; formula-leading CSV cells receive an apostrophe prefix. These protections do not make arbitrary input risk-free.

Cases retain potentially sensitive original-record data in plaintext. Reports include source filenames, hashes, timestamps, and observed IPs. CSV exports include event text. Store and share them according to the data's sensitivity. File permissions and encryption are managed by the operating system. No automatic deletion or retention policy is applied.

Use cases created by this app and work from copies of original logs. Do not edit source files while importing. No original source file is modified. An import failure rolls back that file, while earlier files in a multiple-file operation remain committed. Per-file SHA-256 deduplication does not deduplicate overlapping events from different exports.

Windows decoding launches trusted OS tools with fixed arguments. EVTX paths are passed as environment data to a bundled fixed PowerShell command, never interpolated into source code. ETL paths are passed as individual arguments to `tracerpt.exe` without a shell. The app does not change execution policy, elevate, install providers, start traces, or request symbols. ETL conversion writes a temporary EVTX file containing sensitive trace data to the operating system's user temporary directory; it is cleaned up on normal completion, errors, and cancellation. An OS/process crash can leave temporary files behind. The user is responsible for the security of the OS temp location. XML DTDs/entity declarations are refused.

The optional developer fixture generator is separate from the application: it starts and stops one private in-process session for a synthetic provider only, without elevation. Generated binaries may contain local trace-header metadata and are excluded from Git and release archives.

Structured text and JSON parsers do not execute templates, expressions, or JSON paths. JSON selection uses literal JSON Pointer segments. Duplicate JSON keys and ambiguous automatic containers fail the whole import. CEF/LEEF/W3C parsing failures retain the original line with a warning, so raw evidence may contain URLs, commands, or active-looking text; those are displayed as text only. HTTP URI/query values are not decoded or fetched. Nested JSON arrays inside an event are preserved rather than guessed into entities. The per-record/chunk/depth limits bound common resource risks but are not a guarantee against every malformed or adversarial vendor file.

If reporting a vulnerability, use GitHub's private vulnerability reporting when the repository owner has enabled it. Do not attach customer logs or credentials to public issues. Synthetic reproductions are preferred.
