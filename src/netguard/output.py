"""Render analysis results as human-readable text or machine-readable JSON."""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from typing import Any, TextIO

from netguard import __version__
from netguard.engine import AnalysisResult
from netguard.models import Alert, Severity

_COLORS = {Severity.HIGH: "\033[1;31m", Severity.MEDIUM: "\033[1;33m", Severity.LOW: "\033[1;36m"}
_RESET, _DIM = "\033[0m", "\033[2m"


def use_color(stream: TextIO) -> bool:
    return stream.isatty() and "NO_COLOR" not in os.environ


def _ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


def format_alert(alert: Alert, color: bool = False) -> str:
    sev = f"[{alert.severity}]"
    if color:
        sev = f"{_COLORS[alert.severity]}{sev}{_RESET}"
    target = f"{alert.src or '?'} -> {alert.dst}" if alert.dst else (alert.src or "?")
    technique = f"  {alert.technique.id} {alert.technique.name}" if alert.technique else ""
    dim, reset = (_DIM, _RESET) if color else ("", "")
    return (
        f"{sev} {alert.title}: {target}{dim}{technique}{reset}\n"
        f"    {alert.summary}\n"
        f"    {dim}{_ts(alert.first_seen)} → {_ts(alert.last_seen)}  detector={alert.detector}{reset}"
    )


def render_text(result: AnalysisResult, source: str, color: bool = False) -> str:
    s = result.stats
    out = [f"NetGuard {__version__} — {source}", ""]
    out.append(
        f"Packets: {s.packets:,}   Bytes: {s.bytes:,}   Duration: {s.duration:.1f}s   "
        f"Flows: {s.flows_total:,}   Decode errors: {s.decode_errors}"
    )
    if s.protocols:
        out.append("Protocols: " + ", ".join(f"{p} {n:,}" for p, n in s.protocols.most_common()))
    if s.bytes_by_ip:
        out.append("Top talkers: " + ", ".join(f"{ip} ({b:,} B)" for ip, b in s.bytes_by_ip.most_common(5)))
    out.append("")
    if not result.alerts:
        out.append("No alerts.")
    else:
        by_sev = {sev: sum(a.severity == sev for a in result.alerts) for sev in Severity}
        counts = ", ".join(f"{n} {sev}" for sev, n in sorted(by_sev.items(), reverse=True) if n)
        out.append(f"Alerts: {len(result.alerts)} ({counts})")
        out.append("")
        out += [format_alert(a, color) + "\n" for a in result.alerts]
    return "\n".join(out).rstrip() + "\n"


def render_json(result: AnalysisResult, source: str) -> str:
    doc: dict[str, Any] = {
        "netguard_version": __version__,
        "source": source,
        "stats": result.stats.to_dict(),
        "alerts": [a.to_dict() for a in result.alerts],
    }
    return json.dumps(doc, indent=2) + "\n"


def write_jsonl_alert(alert: Alert, stream: TextIO | None = None) -> None:
    stream = stream or sys.stdout  # resolved at call time so redirection works
    stream.write(json.dumps(alert.to_dict()) + "\n")
    stream.flush()
