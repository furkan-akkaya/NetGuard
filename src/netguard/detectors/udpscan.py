"""UDP port-scan detection (``nmap -sU``): one source probing many UDP ports of one target.

UDP has no handshake, so "connection attempt" means the first datagram of a
new UDP flow from its originator (the flow table's ``attempt`` event). Using
flows matters: a DNS server *answering* clients on hundreds of ephemeral ports
is the responder of those flows and is never counted as a prober.

Port state comes from the target's reaction:

* a UDP reply from the probed port → **open**;
* ICMP port unreachable (type 3, code 3) quoting the probe → **closed**;
* other ICMP unreachable codes (admin prohibited, host unreachable…) → **filtered**;
* nothing → open|filtered, as nmap reports it.

Many legitimate clients talk to many UDP ports of one host (VoIP media, game
servers, NFS). Unlike a scan, most of those ports *answer*. An incident whose
share of answered ports exceeds ``max_answered_ratio`` is therefore not
reported. Note that Linux rate-limits ICMP errors (about one per second per
destination by default), so most closed ports of a Linux target look silent.
"""

from __future__ import annotations

from collections.abc import Iterable

from netguard.config import Config
from netguard.detectors.base import Detector, RuleInfo, as_early
from netguard.flows import ANSWERED, ATTEMPT, Flow
from netguard.models import Alert, Packet, Severity, Technique
from netguard.window import BurstTracker, Incident

T1046 = Technique("T1046", "Network Service Discovery")
RULE_ID = "NG-SCAN-003"
ICMP_UNREACH = 3
ICMP_PORT_UNREACH = 3

Key = tuple[str, str]  # (scanner, target)


class UdpScanDetector(Detector):
    name = "udpscan"
    packet_protos = frozenset({"icmp"})
    rules = (RuleInfo(RULE_ID, "UDP port scan", T1046),)

    def __init__(self, config: Config) -> None:
        self.cfg = config.udpscan
        self.global_cfg = config
        self.tracker: BurstTracker[Key, int] = BurstTracker(
            window=self.cfg.window_seconds,
            threshold=self.cfg.min_distinct_ports,
            idle_timeout=self.cfg.idle_timeout_seconds,
            max_keys=self.cfg.max_keys,
            max_age=config.alerts.max_incident_age_seconds,
            track_opened=config.alerts.early_warning,
        )
        self.suppressed = 0  # incidents not reported because most ports answered

    def on_conn_event(self, event: str, flow: Flow, ts: float) -> Iterable[Alert]:
        if flow.proto != "udp":
            return ()
        key = (flow.src_ip, flow.dst_ip)
        if event == ATTEMPT and not self.global_cfg.is_allowlisted(flow.src_ip):
            self.tracker.observe(key, ts, flow.dst_port)
        elif event == ANSWERED:
            self.tracker.note_response(key, "open", flow.dst_port)
        return ()

    def on_packet(self, pkt: Packet) -> Iterable[Alert]:
        if pkt.proto != "icmp" or pkt.icmp_type != ICMP_UNREACH or pkt.icmp_orig_proto != "udp":
            return ()
        if pkt.src_ip is None or pkt.dst_ip is None or pkt.icmp_orig_dst_port is None:
            return ()
        # The target (ICMP sender) tells the scanner (ICMP receiver) about the probed port.
        kind = "closed" if pkt.icmp_code == ICMP_PORT_UNREACH else "filtered"
        self.tracker.note_response((pkt.dst_ip, pkt.src_ip), kind, pkt.icmp_orig_dst_port)
        return ()

    def tick(self, now: float) -> Iterable[Alert]:
        early = as_early(self._report(self.tracker.take_opened()))
        return early + self._report(self.tracker.expire(now))

    def flush(self) -> Iterable[Alert]:
        return self._report(self.tracker.drain())

    def _report(self, incidents: list[Incident[Key, int]]) -> list[Alert]:
        alerts = []
        for inc in incidents:
            alert = self._alert(inc)
            if alert is None:
                self.suppressed += 1
            else:
                alerts.append(alert)
        return alerts

    def _ports(self, inc: Incident[Key, int], kind: str) -> list[int]:
        return sorted(p for p in inc.responses.get(kind, ()) if isinstance(p, int) and p in inc.items)

    def _alert(self, inc: Incident[Key, int]) -> Alert | None:
        scanner, target = inc.key
        ports = inc.distinct_items
        open_ports = self._ports(inc, "open")
        closed = self._ports(inc, "closed")
        filtered = self._ports(inc, "filtered")
        if len(open_ports) > self.cfg.max_answered_ratio * ports:
            return None
        silent = max(ports - len(open_ports) - len(closed) - len(filtered), 0)
        severity = Severity.HIGH if ports >= self.cfg.high_severity_ports else Severity.MEDIUM
        summary = (
            f"{scanner} sent UDP datagrams to {ports} distinct ports on {target} in {inc.duration:.1f}s "
            f"(threshold: {self.cfg.min_distinct_ports} ports within {self.cfg.window_seconds:g}s). "
            f"Target reactions: {len(open_ports)} open (UDP reply), {len(closed)} closed (ICMP port unreachable), "
            f"{len(filtered)} filtered (other ICMP unreachable), {silent} silent (open or filtered)."
        )
        if open_ports:
            summary += " Open: " + ", ".join(map(str, open_ports[:15])) + ("…" if len(open_ports) > 15 else "") + "."
        return Alert(
            detector=self.name,
            rule_id=RULE_ID,
            title=self.rules[0].title,
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
                "duration_seconds": round(inc.duration, 3),
                "open_ports": open_ports,
                "closed_ports_count": len(closed),
                "filtered_ports_count": len(filtered),
                "silent_ports_count": silent,
                "sample_ports": sorted(inc.items)[:25],
                "threshold": {
                    "min_distinct_ports": self.cfg.min_distinct_ports,
                    "window_seconds": self.cfg.window_seconds,
                    "max_answered_ratio": self.cfg.max_answered_ratio,
                },
            },
        )
