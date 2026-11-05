import argparse
import json
from . import __version__
from .core import create_case, validate_case, import_file, analyze, load_indicators, summary
from .reports import export_report, export_csv


def main():
    parser = argparse.ArgumentParser(description="Offline Security Log Analyzer. No network access.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command")
    gui = commands.add_parser("gui", help="Launch desktop application (default)")
    gui.add_argument("--case", help="Open an existing case on launch")
    ingest = commands.add_parser("import", help="Create/open a case and stream files into it")
    ingest.add_argument("case")
    ingest.add_argument("files", nargs="+")
    ingest.add_argument("--offset", default="+00:00", help="Timezone for naive timestamps, e.g. +01:00")
    ingest.add_argument("--syslog-year", type=int)
    ingest.add_argument("--format", dest="input_format", default="auto", choices=("auto", "text", "cef", "leef", "w3c", "json", "jsonl"))
    ingest.add_argument("--json-path", default="", help="JSON Pointer to events, e.g. /data/events; $ selects root; blank auto-detects")
    inspect = commands.add_parser("summary")
    inspect.add_argument("case")
    report = commands.add_parser("report")
    report.add_argument("case")
    report.add_argument("output", help=".html or .json")
    report.add_argument("--indicators")
    report.add_argument("--failure-threshold", type=int, default=5)
    report.add_argument("--fanout-threshold", type=int, default=20)
    export = commands.add_parser("export")
    export.add_argument("case")
    export.add_argument("output")
    for field in ("search", "ip", "start", "end", "event_id", "provider"):
        export.add_argument("--" + field.replace("_", "-"), default="")
    args = parser.parse_args()
    try:
        if args.command in (None, "gui"):
            from .gui import run
            run(getattr(args, "case", None))
        elif args.command == "import":
            create_case(args.case)
            validate_case(args.case)
            for path in args.files:
                print(json.dumps(import_file(args.case, path, args.offset, args.syslog_year, print, input_format=args.input_format, json_path=args.json_path)))
        else:
            validate_case(args.case)
            if args.command == "summary":
                print(json.dumps(summary(args.case), indent=2))
            elif args.command == "report":
                if not args.output.lower().endswith((".json", ".html")):
                    raise ValueError("Report output must end with .json or .html")
                networks = load_indicators(args.indicators) if args.indicators else []
                findings = analyze(args.case, networks, args.failure_threshold, args.fanout_threshold)
                export_report(args.case, args.output, findings, {"failure_threshold": args.failure_threshold, "fanout_threshold": args.fanout_threshold, "indicators": [str(n) for n in networks]})
                print(f"Saved {args.output}; {len(findings)} findings")
            elif args.command == "export":
                count = export_csv(args.case, args.output, **{k: getattr(args, k) for k in ("search", "ip", "start", "end", "event_id", "provider")})
                print(f"Exported {count:,} events")
    except Exception as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    main()
