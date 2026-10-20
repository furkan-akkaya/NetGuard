"""The analysis engine: drives packets through the statistics and detectors."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from netguard.config import Config
from netguard.decode import decode
from netguard.detectors import Detector, build_detectors
from netguard.models import Alert, Packet
from netguard.stats import TrafficStats

TICK_SECONDS = 1.0  # how often (in capture time) detectors may close incidents


@dataclass
class AnalysisResult:
    stats: TrafficStats
    alerts: list[Alert] = field(default_factory=list)


class Engine:
    def __init__(
        self,
        config: Config | None = None,
        detectors: list[Detector] | None = None,
        on_alert: Callable[[Alert], None] | None = None,
    ) -> None:
        self.config = config or Config()
        self.detectors = detectors if detectors is not None else build_detectors(self.config)
        self.stats = TrafficStats()
        self.alerts: list[Alert] = []
        self._on_alert = on_alert
        self._next_tick: float | None = None

    def _emit(self, alerts: Iterable[Alert]) -> None:
        for alert in alerts:
            self.alerts.append(alert)
            if self._on_alert:
                self._on_alert(alert)

    def process(self, pkt: Packet) -> None:
        # Tick *before* handing the packet to detectors: an incident that has been
        # idle must be closed first, otherwise this packet would extend it.
        # Ticking on capture time (not wall-clock) keeps offline runs deterministic.
        if self._next_tick is None:
            self._next_tick = pkt.ts + TICK_SECONDS
        elif pkt.ts >= self._next_tick:
            for det in self.detectors:
                self._emit(det.tick(pkt.ts))
            self.stats.expire(pkt.ts)
            self._next_tick = pkt.ts + TICK_SECONDS
        self.stats.add(pkt)
        for det in self.detectors:
            self._emit(det.on_packet(pkt))

    def process_frame(self, ts: float, buf: bytes, linktype: int) -> None:
        pkt = decode(ts, buf, linktype)
        if pkt is None:
            self.stats.decode_errors += 1
            return
        self.process(pkt)

    def finish(self) -> AnalysisResult:
        for det in self.detectors:
            self._emit(det.flush())
        self.alerts.sort(key=lambda a: (a.first_seen, a.detector))
        return AnalysisResult(stats=self.stats, alerts=self.alerts)


def analyze_frames(frames: Iterable[tuple[float, bytes, int]], config: Config | None = None) -> AnalysisResult:
    engine = Engine(config)
    for ts, buf, linktype in frames:
        engine.process_frame(ts, buf, linktype)
    return engine.finish()


def analyze_packets(packets: Iterable[Packet], config: Config | None = None) -> AnalysisResult:
    engine = Engine(config)
    for pkt in packets:
        engine.process(pkt)
    return engine.finish()
