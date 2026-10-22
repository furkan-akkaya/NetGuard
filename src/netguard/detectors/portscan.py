"""Vertical TCP port-scan detection (one source probing many ports of one target).

A *probe* is a TCP segment that opens or pokes at a connection without being
part of one:

* ``SYN`` without ``ACK``            — connect() and SYN ("half-open") scans
* no flags at all                    — NULL scan
* ``FIN`` without ``ACK``            — FIN scan
* ``FIN|PSH|URG`` without ``ACK``    — XMAS scan

The detector counts *distinct destination ports* per ``(source, target)`` pair
inside a sliding time window. Crossing ``min_distinct_ports`` opens an incident;
the incident keeps collecting evidence (including which ports answered SYN-ACK,
i.e. were found *open*) and is reported once it has been idle for
``idle_timeout_seconds`` or the input ends.
"""

from __future__ import annotations

from collections.abc import Iterable

from netguard.config import Config
from netguard.detectors.base import Detector
from netguard.models import ACK, FIN, PSH, RST, SYN, URG, Alert, Packet, Severity, Technique
from netguard.window import BurstTracker, Incident

T1046 = Technique("T1046", "Network Service Discovery")
RULE_ID = "NG-SCAN-001"

Key = tuple[str, str]  # (scanner_ip, target_ip)


def probe_type(flags: int) -> str | None:
    """Classify a TCP flag combination as a scan probe, or ``None`` if it is not one."""
    if flags & ACK:
        return None
    if flags & SYN and not flags & (RST | FIN):
        return "SYN"
    if flags == 0:
        return "NULL"
    if flags & (FIN | PSH | URG) == (FIN | PSH | URG):
        return "XMAS"
    if flags & FIN and not flags & RST:
        return "FIN"
    return None


class PortScanDetector(Detector):
    name = "portscan"

    def __init__(self, config: Config) -> None:
        self.cfg = config.portscan
        self.global_cfg = config
        self.tracker: BurstTracker[Key, int] = BurstTracker(
            window=self.cfg.window_seconds,
            threshold=self.cfg.min_distinct_ports,
            idle_timeout=self.cfg.idle_timeout_seconds,
        )

    def on_packet(self, pkt: Packet) -> Iterable[Alert]:
        if pkt.proto != "tcp" or pkt.tcp_flags is None or pkt.src_ip is None or pkt.dst_ip is None:
            return ()
        flags = pkt.tcp_flags
        kind = probe_type(flags)
        if kind is not None:
            if not self.global_cfg.is_allowlisted(pkt.src_ip):
                assert pkt.dst_port is not None
                self.tracker.observe((pkt.src_ip, pkt.dst_ip), pkt.ts, pkt.dst_port, kind)
            return ()

        # A reply from the target to the scanner reveals the port state.
        key = (pkt.dst_ip, pkt.src_ip)
        if flags & SYN and flags & ACK:
            self.tracker.note_response(key, "open", pkt.src_port)
        elif flags & RST:
            self.tracker.note_response(key, "closed", pkt.src_port)
        return ()

    def tick(self, now: float) -> Iterable[Alert]:
        return [self._alert(inc) for inc in self.tracker.expire(now)]

    def flush(self) -> Iterable[Alert]:
        return [self._alert(inc) for inc in self.tracker.drain()]

    def _alert(self, inc: Incident[Key, int]) -> Alert:
        scanner, target = inc.key
        ports = inc.distinct_items
        open_ports = sorted(p for p in inc.responses.get("open", ()) if isinstance(p, int))
        closed = len(inc.responses.get("closed", ()))
        unanswered = max(ports - len(open_ports) - closed, 0)
        severity = Severity.HIGH if ports >= self.cfg.high_severity_ports else Severity.MEDIUM
        probe_kinds = ", ".join(f"{k}={v}" for k, v in sorted(inc.tags.items()))
        stealth = sorted(k for k in inc.tags if k != "SYN")

        summary = (
            f"{scanner} probed {ports} distinct TCP ports on {target} in {inc.duration:.1f}s "
            f"(threshold: {self.cfg.min_distinct_ports} ports within {self.cfg.window_seconds:g}s). "
            f"Probes: {probe_kinds}. Target replies: {len(open_ports)} open, {closed} closed, "
            f"{unanswered} unanswered."
        )
        if open_ports:
            summary += f" Open: {_fmt_ports(open_ports)}."
        if stealth:
            summary += f" Non-SYN probe types ({', '.join(stealth)}) indicate a deliberate stealth scan."

        return Alert(
            detector=self.name,
            rule_id=RULE_ID,
            title="TCP port scan",
            severity=severity,
            first_seen=inc.first_seen,
            last_seen=inc.last_seen,
            src=scanner,
            dst=target,
            technique=T1046,
            summary=summary,
            evidence={
                "distinct_ports": ports,
                "probes": inc.events,
                "probe_types": dict(inc.tags),
                "duration_seconds": round(inc.duration, 3),
                "probes_per_second": round(inc.events / inc.duration, 2) if inc.duration > 0 else None,
                "open_ports": open_ports,
                "closed_ports_count": closed,
                "unanswered_ports_count": unanswered,
                "sample_ports": sorted(inc.items)[:25],
                "threshold": {
                    "min_distinct_ports": self.cfg.min_distinct_ports,
                    "window_seconds": self.cfg.window_seconds,
                },
            },
        )


def _fmt_ports(ports: list[int], limit: int = 15) -> str:
    shown = ", ".join(map(str, ports[:limit]))
    return shown + (f" (+{len(ports) - limit} more)" if len(ports) > limit else "")
