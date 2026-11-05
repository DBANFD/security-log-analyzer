"""Generate synthetic samples only. No customer data."""
import csv
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path


def generate(folder, count=200):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    base = datetime(2026, 1, 15, 10, tzinfo=timezone.utc)
    with (folder / "defender-demo.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "DeviceName", "AccountName", "LocalIP", "RemoteIP", "ActionType", "Message"])
        for i in range(count):
            writer.writerow([(base + timedelta(seconds=i * 3)).isoformat(), f"demo-host-{i % 8 + 1:02}", "demo-user", "10.10.0.25" if i < 30 else f"10.10.0.{i % 8 + 1}", f"192.0.2.{i % 200 + 1}", "ConnectionSuccess", "Synthetic network event"])
    with (folder / "sentinel-demo.jsonl").open("w", encoding="utf-8") as f:
        for i in range(8):
            f.write(json.dumps({"TimeGenerated": (base + timedelta(seconds=i * 10)).isoformat(), "Computer": "demo-auth", "SourceIP": "203.0.113.42", "EventID": 4625, "Message": "Synthetic logon failure"}) + "\n")
    (folder / "syslog-demo.log").write_text("".join(f"<34>1 2026-01-15T10:01:{i:02}Z demo-linux sshd - - - Failed password for demo-user from 203.0.113.42 port 22\n" for i in range(3)), encoding="utf-8")
    (folder / "firewall-demo.log").write_text('date=2026-01-15 time=10:02:00 devname="demo-fw" srcip=10.10.0.25 dstip=192.0.2.10 action=deny msg="Synthetic firewall policy event"\n', encoding="utf-8")
    (folder / "indicators.txt").write_text("# Synthetic documentation-range addresses. Not real threat intelligence.\n203.0.113.42\n192.0.2.10/32\n", encoding="utf-8")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("folder", nargs="?", default="samples")
    parser.add_argument("--count", type=int, default=200)
    args = parser.parse_args()
    generate(args.folder, args.count)
