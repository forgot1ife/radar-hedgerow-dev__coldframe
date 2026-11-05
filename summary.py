"""Summarise recent decoy events. Reads events.jsonl on stdin.

    python3 -I summary.py [--hours N] [--ignore IP ...] < events.jsonl
"""

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

parser = argparse.ArgumentParser()
parser.add_argument("--hours", type=int, default=24)
parser.add_argument("--ignore", nargs="*", default=[], help="source IPs to leave out, e.g. your own")
args = parser.parse_args()


def safe(text):
    """Log fields are attacker-controlled: neutralise terminal escape codes."""
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in str(text))


since = datetime.now(timezone.utc) - timedelta(hours=args.hours)

events = []
for line in sys.stdin:
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if e.get("proto") == "system" or e.get("src_ip") in args.ignore:
        continue
    if datetime.fromisoformat(e["ts"]) >= since:
        events.append(e)

ips = Counter(e["src_ip"] for e in events)
logins = Counter((e["username"], e["password"]) for e in events if e["event"] == "login_attempt")
paths = Counter(e["path"] for e in events if e["event"] == "request")
exploits = Counter(e["exploit"] for e in events if e.get("exploit"))
writes = [e for e in events if e["event"] == "write"]
defrost = [e for e in writes if e.get("defrost")]
modbus_ips = {e["src_ip"] for e in events if e["proto"] == "modbus"}

print(f"Fridge decoy, last {args.hours}h: {len(events)} events from {len(ips)} IPs")
print(f"  logins tried: {sum(logins.values())}   exploit attempts: {sum(exploits.values())}   "
      f"modbus sources: {len(modbus_ips)}   register writes: {len(writes)}   "
      f"DEFROST attempts: {len(defrost)}")
for title, counter in (("Exploits", exploits), ("Top IPs", ips),
                       ("Top credentials", logins), ("Top paths", paths)):
    if counter:
        print(f"\n{title}:")
        for key, n in counter.most_common(10):
            label = f"{key[0]} / {key[1]}" if isinstance(key, tuple) else key
            print(f"  {n:5}  {safe(label)[:100]}")
for e in defrost:
    print(f"\nDEFROST {safe(e['ts'])} from {safe(e['src_ip'])}: "
          f"fc={e['fc']} start={e['start']} values={e['values']}")
