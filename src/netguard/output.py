"""Render analysis results as human-readable text or machine-readable JSON."""

from __future__ import annotations

import csv
import json
import os
import sys
from datetime import UTC, datetime
from typing import Any, TextIO

from netguard import __version__
from netguard.engine import AnalysisResult
from netguard.flows import Flow
from netguard.formats import CaptureInfo
from netguard.models import ALERT_SCHEMA_VERSION, Alert, Severity

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
    if alert.stage == "early":
        sev = f"{sev} EARLY"  # provisional: the incident is still open
    dim, reset = (_DIM, _RESET) if color else ("", "")
    return (
        f"{sev} {alert.title}: {target}{dim}{technique}{reset}\n"
        f"    {alert.summary}\n"
        f"    {dim}{_ts(alert.first_seen)} → {_ts(alert.last_seen)}  "
        f"rule={alert.rule_id} detector={alert.detector}{reset}"
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
    if s.conn_states:
        out.append("Flow states: " + ", ".join(f"{st} {n:,}" for st, n in s.conn_states.most_common()))
    if s.services:
        out.append("Top services (flows): " + ", ".join(f"{svc} {n:,}" for svc, n in s.services.most_common(5)))
    if s.endpoints:
        approx = " (approximate)" if s.endpoints_approximate else ""
        talkers = ", ".join(f"{ip} ({ep.total_bytes:,} B)" for ip, ep in s.top_endpoints(5))
        out.append(f"Top talkers{approx}: {talkers}")
    if s.retransmissions:
        out.append(f"TCP retransmissions: {s.retransmissions:,}")
    for linktype, n in sorted(s.unsupported_linktypes.items()):
        out.append(f"Warning: {n:,} frames skipped, unsupported link type {linktype}")
    if s.flows_evicted:
        out.append(f"Warning: {s.flows_evicted:,} flows evicted early because the flow table was full (max_flows)")
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


def render_json(result: AnalysisResult, source: str, capture: CaptureInfo | None = None) -> str:
    doc: dict[str, Any] = {
        "schema_version": ALERT_SCHEMA_VERSION,
        "netguard_version": __version__,
        "source": source,
        "capture": capture.to_dict() if capture else None,
        "stats": result.stats.to_dict(),
        "alerts": [a.to_dict() for a in result.alerts],
    }
    return json.dumps(doc, indent=2) + "\n"


def write_jsonl_alert(alert: Alert, stream: TextIO | None = None) -> None:
    stream = stream or sys.stdout  # resolved at call time so redirection works
    stream.write(json.dumps(alert.to_dict()) + "\n")
    stream.flush()


FLOW_FIELDS = (
    "proto",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "first_seen",
    "last_seen",
    "duration_seconds",
    "state",
    "history",
    "orig_packets",
    "orig_bytes",
    "orig_payload_bytes",
    "resp_packets",
    "resp_bytes",
    "resp_payload_bytes",
    "retransmissions",
    "seq_gaps",
    "end_reason",
)


class FlowWriter:
    """Stream finished flows as CSV or JSON Lines."""

    def __init__(self, fmt: str, stream: TextIO | None = None) -> None:
        self.fmt = fmt
        self.stream = stream or sys.stdout
        self._csv: csv.DictWriter[str] | None = None
        if fmt == "csv":
            self._csv = csv.DictWriter(self.stream, fieldnames=FLOW_FIELDS, lineterminator="\n")
            self._csv.writeheader()

    def write(self, flow: Flow) -> None:
        row = flow.to_dict()
        if self._csv is not None:
            self._csv.writerow(row)
        else:
            self.stream.write(json.dumps(row) + "\n")
