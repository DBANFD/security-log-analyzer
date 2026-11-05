"""Reproducible synthetic benchmark; generated data stays under work/."""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from generate_demo import generate
from security_log_analyzer.core import create_case, import_file, analyze, summary


def peak_memory_mb():
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [(name, ctypes.c_size_t) for name in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        return round(counters.PeakWorkingSetSize / 1024**2, 1)
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=1000000)
    parser.add_argument("--folder", default="work/benchmark")
    args = parser.parse_args()
    folder = Path(args.folder)
    case = folder / "benchmark.sqlite"
    if case.exists():
        parser.error("Benchmark case already exists; select a fresh --folder.")
    generate(folder, args.count)
    create_case(case)
    source = folder / "defender-demo.csv"
    start = time.perf_counter()
    imported = import_file(case, source)
    elapsed = time.perf_counter() - start
    print(f"Imported {imported['records']:,} in {elapsed:.2f}s", flush=True)
    start = time.perf_counter()
    findings = analyze(case)
    stats = summary(case)
    result = {"python": sys.version.split()[0], "platform": sys.platform, "events": stats["events"], "source_mib": round(source.stat().st_size / 1024**2, 1), "database_mib": round(case.stat().st_size / 1024**2, 1), "import_seconds": round(elapsed, 2), "analysis_and_summary_seconds": round(time.perf_counter() - start, 2), "peak_process_working_set_mib": peak_memory_mb(), "finding_count": len(findings), "rejected": imported["rejected"]}
    (folder / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
