"""Core data types shared by every NetGuard component.

The pipeline is: raw frame -> :class:`Packet` (normalized, protocol-agnostic view)
-> detectors -> :class:`Alert`. Keeping these types small and immutable makes the
detectors easy to unit-test: a test only needs to construct ``Packet`` objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any

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
    proto: str  # "tcp", "udp", "icmp", "icmp6", "arp", "ip-other", "other"
    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    arp_op: int | None = None  # 1 = request, 2 = reply
    arp_sender_mac: str | None = None
    arp_sender_ip: str | None = None
    arp_target_mac: str | None = None
    arp_target_ip: str | None = None
    dns_query: str | None = None


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
    title: str
    severity: Severity
    first_seen: float
    last_seen: float
    summary: str
    src: str | None = None
    dst: str | None = None
    technique: Technique | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "title": self.title,
            "severity": str(self.severity),
            "first_seen": _iso(self.first_seen),
            "last_seen": _iso(self.last_seen),
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


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).isoformat(timespec="milliseconds")
