"""Core data types shared by every NetGuard component.

The pipeline is: raw frame -> :class:`Packet` (normalized, protocol-agnostic view)
-> detectors -> :class:`Alert`. Keeping these types small and immutable makes the
detectors easy to unit-test: a test only needs to construct ``Packet`` objects.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any

from netguard.dns import DnsInfo

#: Version of the alert JSON contract. Bump the major on breaking changes
#: (renamed/removed fields), the minor when fields are added.
ALERT_SCHEMA_VERSION = "1.1"

#: Alert stages (ADR-0010). ``early``: the incident just crossed its threshold
#: and is still open; ``final``: the incident closed. Both share one alert_id.
STAGE_EARLY, STAGE_FINAL = "early", "final"

# The unspecified address: used as ARP sender IP by hosts without an address yet.
UNSPECIFIED_IPV4 = "0.0.0.0"  # noqa: S104 - compared against, never bound

# TCP flag bits (RFC 793 / RFC 3168).
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


@dataclass(frozen=True, slots=True)
class Packet:
    """A decoded frame, flattened to the fields detectors care about.

    Fields that do not apply to a given protocol are ``None``. ``ts`` is the
    capture timestamp (seconds since the epoch); detectors must use it instead of
    the wall clock so that offline analysis is deterministic and reproducible.
    """

    ts: float
    length: int
    proto: str  # "tcp", "udp", "icmp", "icmp6", "arp", "ip-frag", "ip-other", "other"
    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int | None = None
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    # Bytes of L4 payload according to the IP length field, so the value is
    # right even when the capture snaplen truncated the frame.
    payload_len: int | None = None
    ttl: int | None = None  # IPv4 TTL or IPv6 hop limit
    # True for any IPv4 fragment. Non-first fragments carry no L4 header and are
    # decoded with ``proto="ip-frag"``.
    fragment: bool = False
    frag_offset: int = 0  # bytes
    frag_more: bool = False  # the More Fragments flag
    ip_proto: int | None = None  # IP protocol number (6 TCP, 17 UDP, 1 ICMP, ...)
    icmp_type: int | None = None
    icmp_code: int | None = None
    arp_op: int | None = None  # 1 = request, 2 = reply
    arp_sender_mac: str | None = None
    arp_sender_ip: str | None = None
    arp_target_mac: str | None = None
    arp_target_ip: str | None = None
    # ICMP destination unreachable: protocol and destination port of the
    # original datagram quoted inside the message (port unreachable = closed UDP port).
    icmp_orig_proto: str | None = None
    icmp_orig_dst_port: int | None = None
    dns: DnsInfo | None = None  # UDP port 53, queries and responses

    @property
    def dns_query(self) -> str | None:
        """First question name of a DNS *query* (not a response), if any."""
        if self.dns is None or self.dns.response:
            return None
        return self.dns.qname


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True, slots=True)
class Technique:
    """A MITRE ATT&CK technique reference, so alerts map to a shared vocabulary."""

    id: str
    name: str

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"


@dataclass(frozen=True, slots=True)
class Alert:
    """An explainable detection result.

    ``summary`` is a one-line, human-readable explanation that states *why* the
    alert fired (observed values versus thresholds). ``evidence`` carries the same
    facts in machine-readable form for JSON output and SIEM ingestion.
    """

    detector: str
    rule_id: str
    title: str
    severity: Severity
    first_seen: float
    last_seen: float
    summary: str
    src: str | None = None
    dst: str | None = None
    technique: Technique | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    stage: str = STAGE_FINAL
    # Capture-clock time at which the alert was emitted (set by the engine);
    # reported_at - first_seen is the detection delay.
    reported_at: float | None = None

    @property
    def alert_id(self) -> str:
        """Deterministic identifier: the same capture and config give the same id.

        Derived from what identifies the incident (rule, entities, start time),
        so re-running an analysis or replaying a capture does not create
        "new" alerts, and downstream systems can de-duplicate on it.
        """
        material = f"{self.rule_id}|{self.src}|{self.dst}|{self.first_seen:.6f}"
        return hashlib.sha256(material.encode()).hexdigest()[:20]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ALERT_SCHEMA_VERSION,
            "alert_id": self.alert_id,
            "stage": self.stage,
            "rule_id": self.rule_id,
            "detector": self.detector,
            "title": self.title,
            "severity": str(self.severity),
            "first_seen": iso_ts(self.first_seen),
            "last_seen": iso_ts(self.last_seen),
            "reported_at": iso_ts(self.reported_at) if self.reported_at is not None else None,
            "src": self.src,
            "dst": self.dst,
            "summary": self.summary,
            "technique": (
                {"id": self.technique.id, "name": self.technique.name, "url": self.technique.url}
                if self.technique
                else None
            ),
            "evidence": self.evidence,
        }


def iso_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).isoformat(timespec="milliseconds")
