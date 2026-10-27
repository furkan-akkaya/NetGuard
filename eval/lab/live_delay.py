"""Reporting delay of a LIVE run, from its JSONL output (task 8.11c).

    uv run python eval/lab/live_delay.py LIVE.jsonl [--pcap CAPTURE.pcap]

For every alert event of a `netguard monitor -f jsonl` run (early warnings on,
as victim-live-rss.sh runs it) this prints:

* reported - last_seen: how old the newest evidence packet was when NetGuard
  reported. This is NOT the delay after the threshold was crossed: an
  incident keeps collecting packets until the next tick reports it, so the
  newest packet is usually much later than the one that crossed the threshold.
* reported - first_seen: time from the first packet of the incident. Any
  traffic between the same hosts counts (on the lab, the bridge's control
  connections start before the scan), so this is not "time since the attack
  started" either.

With --pcap (the pcap written by the same run) it also replays the capture
through the same detectors, ticking after every packet, and finds for each
early warning the packet that crossed its threshold:

* reported - threshold_crossed: NetGuard's own live latency from the
  threshold-crossing packet to the report.

Packet times come from the kernel's capture clock, reported_at from the
system clock of the same host. Only meaningful for a live run on the capture
host; for an offline analysis reported_at is synthetic. Exits 1 when the run
has no early warning, or with --pcap when an early warning has no matching
threshold crossing in the replay.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from netguard import engine as engine_module
from netguard.config import Config
from netguard.models import Alert
from netguard.sources import open_capture


def _ts(value: str) -> float:
    return datetime.fromisoformat(value).timestamp()


def _key(rule_id: str, src: Any, dst: Any) -> tuple[str, str, str]:
    return rule_id, str(src), str(dst)


def threshold_crossings(pcap: Path) -> dict[tuple[str, str, str], float]:
    """(rule, src, dst) -> capture time of the packet after which the early warning opened."""
    config = Config()
    config.alerts.early_warning = True
    crossed: dict[tuple[str, str, str], float] = {}
    last_ts: list[float] = []

    def on_alert(alert: Alert) -> None:
        # With a tick before every packet, an incident opened by packet k is
        # reported at the tick before packet k+1: packet k crossed the threshold.
        if alert.stage == "early" and last_ts:
            crossed.setdefault(_key(alert.rule_id, alert.src, alert.dst), last_ts[0])

    tick = engine_module.TICK_SECONDS
    engine_module.TICK_SECONDS = 0.0  # tick at every packet, not once per second
    try:
        engine = engine_module.Engine(config, on_alert=on_alert)
        with open_capture(pcap) as frames:
            for ts, buf, linktype in frames:
                engine.process_frame(ts, buf, linktype)
                last_ts[:] = [ts]
        engine.finish()
    finally:
        engine_module.TICK_SECONDS = tick
    return crossed


def delays(path: Path, crossings: dict[tuple[str, str, str], float] | None = None) -> list[dict[str, object]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        alert = json.loads(line)
        if not alert.get("reported_at"):
            continue
        reported = _ts(alert["reported_at"])
        row: dict[str, object] = {
            "stage": alert["stage"],
            "rule_id": alert["rule_id"],
            "entity": f"{alert.get('src')}->{alert.get('dst')}",
            "after_newest_evidence_s": round(reported - _ts(alert["last_seen"]), 3),
            "after_incident_first_seen_s": round(reported - _ts(alert["first_seen"]), 3),
        }
        if crossings is not None and alert["stage"] == "early":
            crossed = crossings.get(_key(alert["rule_id"], alert.get("src"), alert.get("dst")))
            row["after_threshold_crossed_s"] = round(reported - crossed, 6) if crossed is not None else None
        rows.append(row)
    return rows


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    pcap = None
    if "--pcap" in argv:
        i = argv.index("--pcap")
        pcap = Path(argv[i + 1]) if i + 1 < len(argv) else None
        args = [a for a in args if Path(a) != pcap]
        if pcap is None or not pcap.is_file():
            print(__doc__, file=sys.stderr)
            return 2
    if len(args) != 1 or not Path(args[0]).is_file():
        print(__doc__, file=sys.stderr)
        return 2
    rows = delays(Path(args[0]), threshold_crossings(pcap) if pcap else None)
    print(json.dumps(rows, indent=2))
    early = [r for r in rows if r["stage"] == "early"]
    if not early:
        print("no early warning in this run: the early-warning delay was NOT measured", file=sys.stderr)
        return 1
    newest = max(float(str(r["after_newest_evidence_s"])) for r in early)
    print(
        f"{len(early)} early warning(s); newest evidence was at most {newest:.3f}s old when reported "
        "(evidence age, not the delay after the threshold)",
        file=sys.stderr,
    )
    if pcap is None:
        print("threshold-crossing delay not computed: pass --pcap with the run's capture", file=sys.stderr)
        return 0
    missing = [r for r in early if r.get("after_threshold_crossed_s") is None]
    if missing:
        print(f"{len(missing)} early warning(s) without a threshold crossing in the replay", file=sys.stderr)
        return 1
    worst = max(float(str(r["after_threshold_crossed_s"])) for r in early)
    print(f"largest delay after the threshold-crossing packet: {worst:.3f}s", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
