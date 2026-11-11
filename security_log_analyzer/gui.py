"""Native desktop interface. Long-running operations stay off the Tk thread."""
import json
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from .core import create_case, validate_case, import_file, summary, query_events, analyze, load_indicators, load_custom_rules, add_annotation, list_annotations, delete_annotation, source_timeline
from .reports import export_csv, export_report
from . import __version__

BG, PANEL, TEXT, MUTED, ACCENT = "#101321", "#1b2033", "#edf0fa", "#a5aec6", "#aa8dff"


class App:
    def __init__(self, root):
        self.root = root
        self.case = None
        self.busy = False
        self.cancel = threading.Event()
        self.messages: queue.Queue = queue.Queue()
        self.networks = []
        self.findings = []
        self.events = []
        self.after_id = 0
        self.active_filters = dict(search="", ip="", start="", end="", event_id="", provider="")
        root.title(f"Security Log Analyzer {__version__} | Local workspace")
        root.geometry("1320x860")
        root.minsize(1200, 720)
        root.configure(bg=BG)
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("TButton", background="#30364f", padding=(12, 8), borderwidth=0)
        style.map("TButton", background=[("active", "#514477"), ("disabled", "#222638")], foreground=[("disabled", "#777f98")])
        style.configure("Accent.TButton", background="#6246a3")
        style.configure("TEntry", fieldbackground=PANEL, foreground=TEXT, insertcolor=TEXT, padding=6)
        style.configure("TCombobox", fieldbackground=PANEL, background=PANEL, foreground=TEXT, arrowcolor=ACCENT, padding=4)
        style.map("TCombobox", fieldbackground=[("readonly", PANEL)], foreground=[("readonly", TEXT)])
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT, rowheight=29, borderwidth=0)
        style.configure("Treeview.Heading", background="#30364f", foreground=TEXT, padding=8)
        style.map("Treeview", background=[("selected", "#514477")])
        style.configure("TNotebook", borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, padding=(18, 10))
        style.map("TNotebook.Tab", background=[("selected", "#514477")])
        outer = ttk.Frame(root, padding=22)
        outer.pack(fill="both", expand=True)
        heading = ttk.Frame(outer)
        heading.pack(fill="x")
        ttk.Label(heading, text="SECURITY / LOCAL INTELLIGENCE", foreground=ACCENT, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Label(heading, text="Security Log Analyzer", font=("Segoe UI", 26, "bold")).pack(anchor="w", pady=(5, 0))
        ttk.Label(heading, text="Investigate exports. Connect evidence. Keep data local.", foreground=MUTED).pack(anchor="w", pady=(3, 16))
        toolbar = ttk.Frame(outer)
        toolbar.pack(fill="x")
        self.buttons = []
        for label, callback in (("New case", self.new_case), ("Open case", self.open_case), ("Import logs", self.ingest), ("Load IP indicators", self.indicators), ("Analyze case", self.analyze), ("Export report", self.report)):
            button = ttk.Button(toolbar, text=label, command=callback, style="Accent.TButton" if label == "Import logs" else "TButton")
            button.pack(side="left", padx=(0, 8))
            self.buttons.append(button)
        self.case_label = ttk.Label(outer, text="No case open. Create a case, then import logs or the included synthetic samples.", foreground=MUTED)
        self.case_label.pack(anchor="w", pady=12)
        settings = ttk.Frame(outer)
        settings.pack(fill="x", pady=(0, 12))
        self.offset, self.year, self.failure, self.fanout = (tk.StringVar(value=v) for v in ("+00:00", "", "5", "20"))
        for label, variable, width in (("Naive-time offset", self.offset, 8), ("Syslog year (optional)", self.year, 6), ("Auth threshold", self.failure, 5), ("Fan-out threshold", self.fanout, 5)):
            ttk.Label(settings, text=label, foreground=MUTED).pack(side="left", padx=(0, 6))
            ttk.Entry(settings, textvariable=variable, width=width).pack(side="left", padx=(0, 18))
        import_settings = ttk.Frame(outer)
        import_settings.pack(fill="x", pady=(0, 12))
        self.input_format = tk.StringVar(value="auto")
        self.json_path = tk.StringVar()
        ttk.Label(import_settings, text="Input format", foreground=MUTED).pack(side="left", padx=(0, 6))
        ttk.Combobox(import_settings, textvariable=self.input_format, values=("auto", "text", "cef", "leef", "w3c", "json", "jsonl"), state="readonly", width=10).pack(side="left", padx=(0, 18))
        ttk.Label(import_settings, text="JSON path", foreground=MUTED).pack(side="left", padx=(0, 6))
        ttk.Entry(import_settings, textvariable=self.json_path, width=28).pack(side="left", padx=(0, 12))
        ttk.Label(import_settings, text="Optional: /data/events or $ for root. Blank = automatic.", foreground=MUTED).pack(side="left")
        self.cards = tk.StringVar(value="0 EVENTS     /     0 HOSTS     /     0 SOURCES     /     0 UNDATED")
        tk.Label(outer, textvariable=self.cards, bg=PANEL, fg=TEXT, font=("Segoe UI", 15, "bold"), anchor="w", padx=20, pady=20).pack(fill="x", pady=(0, 16))
        tabs = ttk.Notebook(outer)
        tabs.pack(fill="both", expand=True)
        overview, events, findings, sources, notes = [ttk.Frame(tabs, padding=12) for _ in range(5)]
        for page, name in zip((overview, events, findings, sources, notes), ("Overview", "Event explorer", "Findings", "Sources & quality", "Notes")):
            tabs.add(page, text=name)
        self.overview = tk.Text(overview, bg=PANEL, fg=TEXT, font=("Consolas", 11), relief="flat", padx=18, pady=14, wrap="word", state="disabled", height=10)
        self.overview.pack(fill="both", expand=True)
        self.write_overview("LOCAL BY DESIGN\n\nAll analysis runs on this machine. No telemetry, API keys, external fonts, or network services.\n\nGET STARTED\n\n1. Create a case database in a folder you control.\n2. Import Windows events, CEF/LEEF, W3C, nested JSON, CSV/TSV, or text logs.\n3. Review Sources & quality for decode warnings, missing dates, and rejected records.\n4. Analyze, inspect findings, and export a local report.\n\nPublic IPs alone are not suspicious. Findings are explainable leads, not verdicts.\n\nUse samples/ for a synthetic walkthrough. The README describes field mapping and rule limits.")
        searchbar = ttk.Frame(events)
        searchbar.pack(fill="x", pady=(0, 8))
        self.filter_vars = {}
        for key, label, width in (("search", "Text", 20), ("ip", "Exact IP", 18), ("start", "From UTC", 17), ("end", "To UTC", 17)):
            ttk.Label(searchbar, text=label).pack(side="left", padx=(0, 5))
            var = tk.StringVar()
            self.filter_vars[key] = var
            ttk.Entry(searchbar, textvariable=var, width=width).pack(side="left", padx=(0, 10))
        actions = ttk.Frame(events)
        actions.pack(fill="x", pady=(0, 8))
        windows_filters = ttk.Frame(events)
        windows_filters.pack(fill="x", pady=(0, 8), before=actions)
        for key, label, width in (("event_id", "Event ID (exact)", 10), ("provider", "Provider (exact)", 46)):
            ttk.Label(windows_filters, text=label).pack(side="left", padx=(0, 5))
            var = tk.StringVar()
            self.filter_vars[key] = var
            ttk.Entry(windows_filters, textvariable=var, width=width).pack(side="left", padx=(0, 10))
        for label, callback in (("Apply filters", self.search), ("Next 500", self.next_page), ("Export matching CSV", self.export_events)):
            button = ttk.Button(actions, text=label, command=callback)
            button.pack(side="left", padx=(0, 8))
            self.buttons.append(button)
        ttk.Label(actions, text="Import order · double-click for full evidence", foreground=MUTED).pack(side="left")
        self.event_tree = self.tree(events, ("id", "timestamp", "host", "src_ip", "dst_ip", "action", "provider", "event_id", "channel", "decode_warning"), (65, 220, 170, 150, 150, 160, 240, 80, 180, 260))
        self.event_tree.bind("<Double-1>", self.evidence)
        ttk.Label(findings, text="Whole-case rules · IP rules use fixed 5-minute UTC buckets · Windows rules match per host · double-click to pivot to evidence", foreground=MUTED).pack(anchor="w", pady=(0, 8))
        self.finding_tree = self.tree(findings, ("rule", "entity", "events", "sources", "reason"), (150, 170, 70, 70, 600))
        self.finding_tree.bind("<Double-1>", lambda event: self.pivot(tabs, events))
        ttk.Label(sources, text="Parse/decode warnings = retained events with incomplete or ambiguous parsing. Inspect event evidence for details.", foreground=MUTED).pack(anchor="w", pady=(0, 8))
        self.source_tree = self.tree(sources, ("id", "name", "records", "rejected", "undated", "assumed", "decode_warnings", "timezone_offset", "syslog_year"), (45, 230, 100, 90, 90, 90, 140, 120, 90))
        note_actions = ttk.Frame(notes)
        note_actions.pack(fill="x", pady=(0, 8))
        for label, callback in (("Refresh notes", self.load_notes), ("Delete selected note", self.remove_note)):
            button = ttk.Button(note_actions, text=label, command=callback)
            button.pack(side="left", padx=(0, 8))
            self.buttons.append(button)
        ttk.Label(note_actions, text="Add tags and notes from an event's evidence window. Notes are analyst opinions, not source evidence.", foreground=MUTED).pack(side="left")
        self.notes = []
        self.note_tree = self.tree(notes, ("event_ref", "timestamp", "host", "src_ip", "event_id", "tag", "note", "created_at"), (80, 200, 160, 140, 80, 140, 420, 180))
        footer = ttk.Frame(outer)
        footer.pack(side="bottom", fill="x", pady=(12, 0), before=tabs)
        self.status = tk.StringVar(value="Ready · Offline workspace")
        ttk.Label(footer, textvariable=self.status, foreground=MUTED).pack(side="left", fill="x", expand=True)
        self.progress = ttk.Progressbar(footer, mode="indeterminate", length=120)
        self.progress.pack(side="left", padx=12)
        self.cancel_button = ttk.Button(footer, text="Cancel import", command=self.cancel.set, state="disabled")
        self.cancel_button.pack(side="right")
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(100, self.poll)

    def tree(self, parent, columns, widths):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for column, width in zip(columns, widths):
            tree.heading(column, text="Parse/decode warnings" if column in ("decode_warning", "decode_warnings") else column.replace("_", " ").title())
            tree.column(column, width=width, minwidth=45)
        y = ttk.Scrollbar(frame, command=tree.yview)
        x = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        tree.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return tree

    def fill(self, tree, rows):
        tree.delete(*tree.get_children())
        for n, row in enumerate(rows):
            tree.insert("", "end", iid=str(n), values=[str(row[k] if row.get(k) is not None else "")[:1000] for k in tree["columns"]])

    def write_overview(self, text):
        self.overview.configure(state="normal")
        self.overview.delete("1.0", "end")
        self.overview.insert("1.0", text)
        self.overview.configure(state="disabled")

    def require_case(self):
        if self.busy:
            return False
        if not self.case:
            messagebox.showinfo("Open a case", "Create or open a case first.")
            return False
        return True

    def work(self, task, done, cancellable=False):
        if self.busy:
            return
        self.busy = True
        self.cancel.clear()
        for button in self.buttons:
            button.configure(state="disabled")
        self.cancel_button.configure(state="normal" if cancellable else "disabled")
        self.progress.start(12)
        self.status.set("Working locally...")
        def worker():
            try:
                self.messages.put(("done", (done, task())))
            except Exception as exc:
                self.messages.put(("error", str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def poll(self):
        try:
            while True:
                kind, value = self.messages.get_nowait()
                if kind == "progress":
                    self.status.set(value)
                    continue
                self.busy = False
                self.progress.stop()
                for button in self.buttons:
                    button.configure(state="normal")
                self.cancel_button.configure(state="disabled")
                if kind == "error":
                    self.status.set("Operation stopped")
                    messagebox.showerror("Operation stopped", value)
                else:
                    callback, result = value
                    self.status.set("Ready · Offline workspace")
                    callback(result)
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def new_case(self):
        path = filedialog.asksaveasfilename(title="Create local case", defaultextension=".sqlite", filetypes=[("Case database", "*.sqlite")])
        if path:
            if Path(path).exists():
                messagebox.showerror("File exists", "Use Open case for an existing file. New case never overwrites a file.")
                return
            try:
                create_case(path)
                self.switch_case(path)
            except Exception as exc:
                messagebox.showerror("Cannot create case", str(exc))

    def open_case(self):
        path = filedialog.askopenfilename(filetypes=[("Case database", "*.sqlite *.db")])
        if path:
            try:
                validate_case(path)
                self.switch_case(path)
            except Exception as exc:
                messagebox.showerror("Cannot open case", str(exc))

    def switch_case(self, path):
        self.case = path
        self.after_id = 0
        self.case_label.configure(text="CASE  /  " + path)
        self.findings = []
        self.networks = []
        self.fill(self.finding_tree, [])
        self.active_filters = dict.fromkeys(self.filter_vars, "")
        for variable in self.filter_vars.values():
            variable.set("")
        self.refresh()

    def refresh(self):
        self.work(lambda: (summary(self.case), query_events(self.case, **self.active_filters), source_timeline(self.case), list_annotations(self.case)), self.render)

    def load_notes(self):
        if self.require_case():
            self.work(lambda: list_annotations(self.case), self.show_notes)

    def show_notes(self, rows):
        self.notes = rows
        self.fill(self.note_tree, rows)

    def remove_note(self):
        selected = self.note_tree.selection()
        if not selected or not self.require_case():
            return
        note = self.notes[int(selected[0])]
        if messagebox.askyesno("Delete note", f"Delete the note on event {note['event_ref']}? The event itself is not changed."):
            self.work(lambda: (delete_annotation(self.case, note["id"]), list_annotations(self.case))[1], self.show_notes)

    def render(self, result):
        stats, events, timeline, notes = result
        self.show_notes(notes)
        self.cards.set(f"{stats['events']:,} EVENTS     /     {stats['hosts']:,} HOSTS     /     {len(stats['imports'])} SOURCES     /     {stats['undated'] or 0:,} UNDATED")
        self.fill(self.source_tree, stats["imports"])
        self.show_events(events)
        lines = ["CASE OVERVIEW", f"UTC coverage: {stats['first'] or 'Unknown'} to {stats['last'] or 'Unknown'}", "", "ACTIVITY / latest 48 populated UTC hours"]
        peak = max((r["count"] for r in stats["timeline"]), default=1)
        for row in stats["timeline"]:
            lines.append(f"{row['hour'].replace('T',' ')}:00  {'█' * max(1, round(row['count']/peak*35))} {row['count']:,}")
        if len(timeline["sources"]) > 1:
            lines += ["", "ACTIVITY BY SOURCE / same hours, one column per source file"]
            names = [f"#{s['id']}" for s in timeline["sources"]]
            lines.append(f"{'UTC hour':<17}" + "".join(f"{n:>10}" for n in names))
            for hour in timeline["hours"]:
                lines.append(f"{hour.replace('T',' ')}:00" + "".join(f"{s['counts'].get(hour, 0) or '.':>10}" for s in timeline["sources"]))
            lines += ["Source numbers match Sources & quality."]
        lines += ["", "TOP IP OBSERVATIONS / source and destination appearances"]
        for row in stats["ips"]:
            lines.append(f"{row['ip']:<40} {row['count']:>8,}   {row['scope']}")
        lines += ["", "Scope is address classification, not reputation. No network lookups are performed.", "Review rejected, undated, and parse/decode warning counts before drawing conclusions."]
        self.write_overview("\n".join(lines))

    def ingest(self):
        if not self.require_case():
            return
        paths = filedialog.askopenfilenames(title="Import local logs", filetypes=[("All supported logs", "*.evtx *.etl *.xml *.csv *.tsv *.json *.jsonl *.ndjson *.cef *.leef *.w3c *.log *.txt *.syslog *.gz"), ("Structured security/web logs", "*.cef *.leef *.w3c *.log"), ("JSON exports", "*.json *.jsonl *.ndjson"), ("Windows events and traces", "*.evtx *.etl *.xml"), ("All files", "*")])
        if not paths:
            return
        try:
            year = int(self.year.get()) if self.year.get().strip() else None
        except ValueError:
            messagebox.showerror("Invalid year", "Enter a four-digit syslog year or leave it blank.")
            return
        offset = self.offset.get()
        input_format, json_path = self.input_format.get(), self.json_path.get().strip()
        self.findings = []
        self.fill(self.finding_tree, [])
        def task():
            results = []
            for path in paths:
                try:
                    result = import_file(self.case, path, offset, year, lambda s: self.messages.put(("progress", s)), self.cancel, input_format, json_path)
                    results.append(f"{Path(path).name}: {result['records']:,} imported; {result['rejected']:,} rejected; {result['undated']:,} undated; {result['decode_warnings']:,} parse/decode warnings")
                except Exception as exc:
                    results.append(f"{Path(path).name}: {exc}")
                if self.cancel.is_set():
                    break
            return results
        def done(results):
            messagebox.showinfo("Import result", "\n".join(results))
            self.refresh()
        self.work(task, done, cancellable=True)

    def indicators(self):
        if not self.require_case():
            return
        path = filedialog.askopenfilename(title="One IP or CIDR per line; # comments allowed", filetypes=[("Text", "*.txt"), ("All", "*")])
        if path:
            try:
                self.networks = load_indicators(path)
                self.findings = []
                self.fill(self.finding_tree, [])
                self.status.set(f"{len(self.networks)} local indicators loaded. Analyze to apply.")
            except Exception as exc:
                messagebox.showerror("Invalid indicators", str(exc))

    def rule_config(self):
        return {"failure_threshold": int(self.failure.get()), "fanout_threshold": int(self.fanout.get()), "indicators": [str(n) for n in self.networks], "windows_rules": True}

    def custom_rules(self, config):
        """Extra rules from windows-rules.json beside the app; None after showing why it is invalid."""
        try:
            rules = load_custom_rules()
        except ValueError as exc:
            messagebox.showerror("Invalid windows-rules.json", str(exc))
            return None
        config["custom_rules"] = [rule[0] for rule in rules]
        return rules

    def analyze(self):
        if not self.require_case():
            return
        try:
            config = self.rule_config()
        except ValueError:
            messagebox.showerror("Invalid thresholds", "Thresholds must be whole numbers, at least two.")
            return
        custom = self.custom_rules(config)
        if custom is None:
            return
        def done(rows):
            self.findings = rows
            self.fill(self.finding_tree, rows)
            self.status.set(f"{len(rows)} findings. Review Findings; indicators require validation.")
        self.work(lambda: analyze(self.case, self.networks, config["failure_threshold"], config["fanout_threshold"], True, custom), done)

    def search(self):
        if not self.require_case():
            return
        self.after_id = 0
        self.active_filters = {k: v.get().strip() for k, v in self.filter_vars.items()}
        self.work(lambda: query_events(self.case, **self.active_filters), self.show_events)

    def show_events(self, rows):
        self.events = rows
        self.after_id = rows[-1]["id"] if rows else self.after_id
        self.fill(self.event_tree, rows)

    def next_page(self):
        if self.require_case():
            self.work(lambda: query_events(self.case, after=self.after_id, **self.active_filters), self.show_events)

    def evidence(self, event):
        selected = self.event_tree.selection()
        if not selected:
            return
        record = self.events[int(selected[0])]
        window = tk.Toplevel(self.root)
        window.title(f"Evidence event {record['id']} | Source {record['import_id']} | Record {record['line']}")
        window.geometry("900x650")
        form = ttk.Frame(window, padding=(12, 10))
        form.pack(side="bottom", fill="x")
        tag, note = tk.StringVar(), tk.StringVar()
        ttk.Label(form, text="Tag").pack(side="left", padx=(0, 5))
        ttk.Entry(form, textvariable=tag, width=18).pack(side="left", padx=(0, 10))
        ttk.Label(form, text="Note").pack(side="left", padx=(0, 5))
        ttk.Entry(form, textvariable=note, width=60).pack(side="left", padx=(0, 10), fill="x", expand=True)
        text = tk.Text(window, bg=PANEL, fg=TEXT, wrap="word", font=("Consolas", 10), padx=18, pady=18)
        text.pack(fill="both", expand=True)
        def show(notes):
            body = json.dumps(record, indent=2, ensure_ascii=False)
            if notes:
                body = "ANALYST NOTES\n" + "\n".join(f"[{n['created_at']}] {n['tag'] or '-'}: {n['note']}" for n in notes) + "\n\n" + body
            text.configure(state="normal")
            text.delete("1.0", "end")
            text.insert("1.0", body)
            text.configure(state="disabled")
        def save():
            try:
                add_annotation(self.case, record["id"], tag.get(), note.get())
            except Exception as exc:
                messagebox.showerror("Note not saved", str(exc), parent=window)
                return
            tag.set("")
            note.set("")
            show(list_annotations(self.case, record["id"]))
            self.show_notes(list_annotations(self.case))
            self.status.set(f"Note saved on event {record['id']}")
        ttk.Button(form, text="Save note", command=save).pack(side="left")
        show(list_annotations(self.case, record["id"]))

    def pivot(self, tabs, events_page):
        selected = self.finding_tree.selection()
        if not selected or self.busy:
            return
        finding = self.findings[int(selected[0])]
        if finding["rule"] == "LIMIT":
            return
        targets = finding.get("pivot") or {"ip": finding["entity"]}
        for key in self.filter_vars:
            self.filter_vars[key].set(targets.get(key, ""))
        tabs.select(events_page)
        self.search()

    def export_events(self):
        if not self.require_case():
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if path and self.safe_output(path):
            self.work(lambda: export_csv(self.case, path, **self.active_filters), lambda n: self.status.set(f"Exported {n:,} matching events to {path}"))

    def safe_output(self, path):
        if Path(path).resolve() == Path(self.case).resolve():  # type: ignore[arg-type]
            messagebox.showerror("Choose another path", "An export cannot overwrite the open case.")
            return False
        return True

    def report(self):
        if not self.require_case():
            return
        try:
            config = self.rule_config()
        except ValueError:
            messagebox.showerror("Invalid thresholds", "Thresholds must be whole numbers.")
            return
        custom = self.custom_rules(config)
        if custom is None:
            return
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML report", "*.html"), ("JSON report", "*.json")])
        if path and self.safe_output(path):
            def task():
                rows = analyze(self.case, self.networks, config["failure_threshold"], config["fanout_threshold"], True, custom)
                export_report(self.case, path, rows, config)
                return rows
            def done(rows):
                self.findings = rows
                self.fill(self.finding_tree, rows)
                self.status.set("Whole-case report saved: " + path)
            self.work(task, done)

    def close(self):
        if self.busy:
            messagebox.showinfo("Operation in progress", "Wait for the current operation to finish. Imports can be cancelled.")
            return
        self.root.destroy()


def run(case=None):
    if case:
        validate_case(case)
    root = tk.Tk()
    app = App(root)
    if case:
        app.switch_case(case)
    root.mainloop()
