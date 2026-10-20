"""Host-discovery sweep detection (one source probing many hosts).

This is the "horizontal" counterpart of the port scan: count *distinct
destination hosts* per source in a sliding window. Probes are:

* ICMP / ICMPv6 echo requests              (``ping`` sweep, ``nmap -sn`` off-LAN)
* ARP requests                             (``nmap -sn`` / ``arp-scan`` on the LAN)
* TCP probes to private addresses          (``nmap -p 445 10.0.0.0/24``)

Replies (echo reply, ARP reply, SYN-ACK/RST) are recorded as *alive hosts*, so
the alert tells an analyst what the attacker learned.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from functools import lru_cache

from netguard.config import Config
from netguard.detectors.base import Detector
from netguard.detectors.portscan import probe_type
from netguard.models import ACK, RST, SYN, UNSPECIFIED_IPV4, Alert, Packet, Severity, Technique
from netguard.window import BurstTracker, Incident

T1018 = Technique("T1018", "Remote System Discovery")

ICMP_ECHO_REQUEST = {"icmp": 8, "icmp6": 128}
ICMP_ECHO_REPLY = {"icmp": 0, "icmp6": 129}
ARP_REQUEST, ARP_REPLY = 1, 2


@lru_cache(maxsize=65_536)
def _is_private(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_private and not addr.is_multicast


@lru_cache(maxsize=65_536)
def _is_unicast(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return not (addr.is_multicast or addr.is_unspecified)


class HostSweepDetector(Detector):
    name = "hostsweep"

    def __init__(self, config: Config) -> None:
        self.cfg = config.hostsweep
        self.global_cfg = config
        self.tracker: BurstTracker[str, str] = BurstTracker(
            window=self.cfg.window_seconds,
            threshold=self.cfg.min_distinct_hosts,
            idle_timeout=self.cfg.idle_timeout_seconds,
        )

    def on_packet(self, pkt: Packet) -> Iterable[Alert]:
        if pkt.proto == "arp":
            self._arp(pkt)
        elif pkt.src_ip is not None and pkt.dst_ip is not None:
            if pkt.proto in ICMP_ECHO_REQUEST:
                self._icmp(pkt)
            elif pkt.proto == "tcp" and pkt.tcp_flags is not None:
                self._tcp(pkt, pkt.tcp_flags)
        return ()

    def _probe(self, src: str, dst: str, ts: float, tag: str) -> None:
        if src != dst and _is_unicast(dst) and not self.global_cfg.is_allowlisted(src):
            self.tracker.observe(src, ts, dst, tag)

    def _arp(self, pkt: Packet) -> None:
        sender, target = pkt.arp_sender_ip, pkt.arp_target_ip
        if sender is None or target is None:
            return
        if pkt.arp_op == ARP_REQUEST:
            if sender != UNSPECIFIED_IPV4:  # skip ARP probes for address conflict detection (RFC 5227)
                self._probe(sender, target, pkt.ts, "ARP")
        elif pkt.arp_op == ARP_REPLY:
            self.tracker.note_response(target, "alive", sender)

    def _icmp(self, pkt: Packet) -> None:
        assert pkt.src_ip is not None
        assert pkt.dst_ip is not None
        if pkt.icmp_type == ICMP_ECHO_REQUEST[pkt.proto]:
            self._probe(pkt.src_ip, pkt.dst_ip, pkt.ts, "ICMP")
        elif pkt.icmp_type == ICMP_ECHO_REPLY[pkt.proto]:
            self.tracker.note_response(pkt.dst_ip, "alive", pkt.src_ip)

    def _tcp(self, pkt: Packet, flags: int) -> None:
        assert pkt.src_ip is not None
        assert pkt.dst_ip is not None
        if probe_type(flags) is not None:
            if not self.cfg.tcp_private_only or _is_private(pkt.dst_ip):
                self._probe(pkt.src_ip, pkt.dst_ip, pkt.ts, "TCP")
        elif (flags & SYN and flags & ACK) or flags & RST:
            self.tracker.note_response(pkt.dst_ip, "alive", pkt.src_ip)

    def tick(self, now: float) -> Iterable[Alert]:
        return [self._alert(inc) for inc in self.tracker.expire(now)]

    def flush(self) -> Iterable[Alert]:
        return [self._alert(inc) for inc in self.tracker.drain()]

    def _alert(self, inc: Incident[str, str]) -> Alert:
        hosts = inc.distinct_items
        alive = sorted((str(ip) for ip in inc.responses.get("alive", ()) if ip in inc.items), key=_ip_sort_key)
        severity = Severity.HIGH if hosts >= self.cfg.high_severity_hosts else Severity.MEDIUM
        methods = ", ".join(f"{k}={v}" for k, v in sorted(inc.tags.items()))
        summary = (
            f"{inc.key} probed {hosts} distinct hosts in {inc.duration:.1f}s "
            f"(threshold: {self.cfg.min_distinct_hosts} hosts within {self.cfg.window_seconds:g}s). "
            f"Methods: {methods}. {len(alive)} hosts replied"
        )
        summary += f": {', '.join(alive[:10])}{' …' if len(alive) > 10 else ''}." if alive else "."
        return Alert(
            detector=self.name,
            title="Host discovery sweep",
            severity=severity,
            first_seen=inc.first_seen,
            last_seen=inc.last_seen,
            src=inc.key,
            technique=T1018,
            summary=summary,
            evidence={
                "distinct_hosts": hosts,
                "probes": inc.events,
                "methods": dict(inc.tags),
                "duration_seconds": round(inc.duration, 3),
                "alive_hosts": alive,
                "sample_targets": sorted(inc.items, key=_ip_sort_key)[:25],
                "threshold": {
                    "min_distinct_hosts": self.cfg.min_distinct_hosts,
                    "window_seconds": self.cfg.window_seconds,
                },
            },
        )


def _ip_sort_key(ip: object) -> tuple[int, int]:
    addr = ipaddress.ip_address(str(ip))
    return (addr.version, int(addr))
