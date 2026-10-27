"""Reporting delay of a LIVE run, from its JSONL output (task 8.11c).

    uv run python eval/lab/live_delay.py LIVE.jsonl

For every alert event of a `netguard monitor -f jsonl` run (early warnings on,
as victim-live-rss.sh runs it) this prints:

* reported - last_seen: wall-clock time from the packet that completed the
  evidence to the moment NetGuard reported it. For an early warning this is
  the packet that crossed the threshold, so it is NetGuard's own live latency.
* reported - first_seen: time from the first packet of the incident, which
  also contains how long the attack took to cross the threshold.

Both timestamps come from the same host: packet times from the kernel's
capture clock, reported_at from the system clock. Only meaningful for a live
run on the capture host; for an offline analysis reported_at is synthetic.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path


def _ts(value: str) -> float:
    return datetime.fromisoformat(value).timestamp()


def delays(path: Path) -> list[dict[str, object]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        alert = json.loads(line)
        if not alert.get("reported_at"):
            continue
        reported = _ts(alert["reported_at"])
        rows.append(
            {
                "stage": alert["stage"],
                "rule_id": alert["rule_id"],
                "entity": f"{alert.get('src')}->{alert.get('dst')}",
                "after_last_seen_s": round(reported - _ts(alert["last_seen"]), 3),
                "after_first_seen_s": round(reported - _ts(alert["first_seen"]), 3),
            }
        )
    return rows


def main(argv: list[str]) -> int:
    if len(argv) != 1 or not Path(argv[0]).is_file():
        print(__doc__, file=sys.stderr)
        return 2
    rows = delays(Path(argv[0]))
    print(json.dumps(rows, indent=2))
    early = [r for r in rows if r["stage"] == "early"]
    if not early:
        print("no early warning in this run: the early-warning delay was NOT measured", file=sys.stderr)
        return 1
    worst = max(float(str(r["after_last_seen_s"])) for r in early)
    print(f"{len(early)} early warning(s); largest delay after the triggering packet: {worst:.3f}s", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
