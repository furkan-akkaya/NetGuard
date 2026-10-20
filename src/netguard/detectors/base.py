"""The detector plugin contract.

A detector is a small state machine fed one packet at a time. It never reads the
wall clock, never does I/O and never raises on unexpected packets, which makes
every detector trivially unit-testable with hand-built ``Packet`` objects.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from netguard.models import Alert, Packet


class Detector(ABC):
    #: Stable identifier used in config, alerts and JSON output.
    name: str = "detector"

    @abstractmethod
    def on_packet(self, pkt: Packet) -> Iterable[Alert]:
        """Consume one packet; return alerts that are ready *now*."""

    def tick(self, now: float) -> Iterable[Alert]:
        """Called periodically with capture time; emit alerts whose evidence is complete."""
        return ()

    def flush(self) -> Iterable[Alert]:
        """End of input: emit everything still pending."""
        return ()
