"""The detector plugin contract.

A detector is a small state machine fed one packet at a time. It never reads the
wall clock, never does I/O and never raises on unexpected packets, which makes
every detector trivially unit-testable with hand-built ``Packet`` objects.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from netguard.config import Config
from netguard.flows import Flow
from netguard.models import Alert, Packet, Technique


@dataclass(frozen=True, slots=True)
class RuleInfo:
    """Static description of a rule a detector can raise (see docs/rules/)."""

    rule_id: str
    title: str
    technique: Technique | None = None


class Detector:
    #: Stable identifier used in config, alerts and JSON output.
    name: str = "detector"
    #: ``Packet.proto`` values ``on_packet`` wants to see; ``None`` = every packet.
    #: The engine dispatches by protocol, so a narrow set is a real speed-up.
    packet_protos: frozenset[str] | None = None
    #: The rules this detector raises; listed by ``netguard rules``.
    rules: tuple[RuleInfo, ...] = ()

    def __init__(self, config: Config) -> None:
        self.global_cfg = config

    def on_packet(self, pkt: Packet) -> Iterable[Alert]:
        """Consume one packet; return alerts that are ready *now*."""
        return ()

    def on_conn_event(self, event: str, flow: Flow, ts: float) -> Iterable[Alert]:
        """A TCP handshake transition (``flows.CONN_EVENTS``) happened at capture time ``ts``."""
        return ()

    def on_flow_end(self, flow: Flow) -> Iterable[Alert]:
        """Consume one finished flow (closed, idle, evicted or end of input)."""
        return ()

    def tick(self, now: float) -> Iterable[Alert]:
        """Called periodically with capture time; emit alerts whose evidence is complete."""
        return ()

    def flush(self) -> Iterable[Alert]:
        """End of input: emit everything still pending."""
        return ()
