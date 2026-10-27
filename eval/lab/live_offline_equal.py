"""Check that live capture and offline analysis of the SAME traffic agree.

    uv run python eval/lab/live_offline_equal.py CAPTURE.pcap LIVE.jsonl [--config c.toml]

CAPTURE.pcap and LIVE.jsonl come from one `netguard monitor --write ... -f jsonl`
run (eval/lab/victim-live-rss.sh). This re-analyses the written capture offline
and compares the set of FINAL alerts with the ones the live run emitted,
keyed by the deterministic alert_id (and shown by rule and entity).

Exit 0 when the final-alert sets are equal, 1 when they differ, 2 on bad input.
Equality is only meaningful when tcpdump reported 0 kernel drops for the
capture (see the capture's .meta.txt); this script prints a reminder and does
not have the drop count itself.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from netguard.config import load_config
from netguard.engine import analyze_frames
from netguard.sources import open_capture


def _entity(alert: dict[str, object]) -> str:
    src, dst = alert.get("src"), alert.get("dst")
    return f"{src}->{dst}" if src and dst else str(src or dst or "?")


def _label(alert: dict[str, object]) -> str:
    return f"{alert.get('rule_id')} {_entity(alert)}"


def live_finals(jsonl: Path) -> dict[str, str]:
    finals: dict[str, str] = {}
    for line in jsonl.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            alert = json.loads(line)
        except ValueError as exc:
            raise SystemExit(f"bad JSONL line in {jsonl}: {exc}") from exc
        if alert.get("stage") == "final":
            finals[str(alert["alert_id"])] = _label(alert)
    return finals


def offline_finals(pcap: Path, config_path: Path | None) -> dict[str, str]:
    config = load_config(config_path)
    config.alerts.early_warning = True  # same pipeline settings as `monitor`
    with open_capture(pcap) as frames:
        result = analyze_frames(frames, config)
    return {a.alert_id: f"{a.rule_id} {a.src or ''}->{a.dst or ''}" for a in result.alerts if a.stage == "final"}


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    config_path = next((Path(a.split("=", 1)[1]) for a in argv if a.startswith("--config=")), None)
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    pcap, jsonl = Path(args[0]), Path(args[1])
    if not pcap.exists() or not jsonl.exists():
        print(f"missing input: {pcap if not pcap.exists() else jsonl}", file=sys.stderr)
        return 2

    live = live_finals(jsonl)
    offline = offline_finals(pcap, config_path)
    only_live = sorted(f"{aid} {label}" for aid, label in live.items() if aid not in offline)
    only_offline = sorted(f"{aid} {label}" for aid, label in offline.items() if aid not in live)

    report = {
        "capture": str(pcap),
        "live_jsonl": str(jsonl),
        "live_final_alerts": len(live),
        "offline_final_alerts": len(offline),
        "matched": len(set(live) & set(offline)),
        "only_live": only_live,
        "only_offline": only_offline,
        "equal": not only_live and not only_offline,
    }
    print(json.dumps(report, indent=2))
    if report["equal"]:
        print("live == offline (check the capture's kernel-drop count is 0 before accepting this)", file=sys.stderr)
        return 0
    print("live != offline: investigate before recording (kernel drops? window-edge timing?)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
