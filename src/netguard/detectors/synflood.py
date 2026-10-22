"""TCP SYN flood detection (many handshakes opened, few completed, one service).

A SYN flood fills a server's backlog of half-open connections: the attacker
sends SYNs and never completes the handshake, often from spoofed source
addresses so the SYN-ACKs go nowhere. The observable signal is therefore not
"many SYNs" (a popular server receives many) but **many new connection
attempts to one ``ip:port`` of which few complete the handshake**.

The detector uses the flow table's connection events, so completion is known
the moment the originator's ACK arrives:

* per target ``(ip, port)`` and fixed interval, count ``attempt``,
  ``answered`` (SYN-ACK), ``rejected`` (RST) and ``established`` events;
* an interval is suspicious when ``attempts >= min_attempts`` and
  ``established / attempts <= max_completion_ratio``;
* consecutive suspicious intervals form one incident, reported once the
  target has had no suspicious interval for ``idle_timeout_seconds``.

The evidence includes source diversity: thousands of distinct sources with one
attempt each suggest spoofing (or a botnet); a single source suggests a tool
such as ``hping3 --flood`` without ``--rand-source``. Port scans spread their
attempts over many ports, so they do not concentrate on one target key.

Memory: at most ``max_targets`` keys (LRU) with at most
``max_sources_per_target`` source counters each.
"""

from __future__ import annotations

from collections import Counter, OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field

from netguard.config import Config
from netguard.detectors.base import Detector, RuleInfo, as_early
from netguard.flows import ANSWERED, ATTEMPT, ESTABLISHED, REJECTED, Flow
from netguard.models import Alert, Severity, Technique

T1499_001 = Technique("T1499.001", "Endpoint Denial of Service: OS Exhaustion Flood")
RULE_ID = "NG-SYN-001"

Target = tuple[str, int]


@dataclass
class _Interval:
    start: float
    attempts: int = 0
    answered: int = 0
    rejected: int = 0
    established: int = 0
    sources: Counter[str] = field(default_factory=Counter)
    sources_overflow: int = 0


@dataclass
class _Incident:
    target: Target
    first_seen: float
    last_seen: float
    attempts: int = 0
    answered: int = 0
    rejected: int = 0
    established: int = 0
    intervals: int = 0
    peak_attempts: int = 0
    sources: Counter[str] = field(default_factory=Counter)
    sources_overflow: int = 0


class SynFloodDetector(Detector):
    name = "synflood"
    rules = (RuleInfo(RULE_ID, "Possible TCP SYN flood", T1499_001),)

    def __init__(self, config: Config) -> None:
        self.cfg = config.synflood
        self._intervals: OrderedDict[Target, _Interval] = OrderedDict()  # least recently updated first
        self._incidents: dict[Target, _Incident] = {}
        self.evicted_targets = 0
        self.early_warning = config.alerts.early_warning
        self.max_age = config.alerts.max_incident_age_seconds
        self._opened: list[Target] = []  # incidents awaiting an early warning

    def _slot(self, ts: float) -> float:
        return (ts // self.cfg.interval_seconds) * self.cfg.interval_seconds

    def on_conn_event(self, event: str, flow: Flow, ts: float) -> Iterable[Alert]:
        if flow.proto != "tcp":
            return ()
        target = (flow.dst_ip, flow.dst_port)
        slot = self._slot(ts)
        cur = self._intervals.get(target)
        if cur is not None and cur.start != slot:
            self._close_interval(target, cur)
            cur = None
        if cur is None:
            if event != ATTEMPT:
                return ()  # outcome of an attempt from an interval already evaluated
            if len(self._intervals) >= self.cfg.max_targets:
                old_target, old = self._intervals.popitem(last=False)
                self._close_interval(old_target, old)
                self.evicted_targets += 1
            cur = self._intervals[target] = _Interval(start=slot)
        else:
            self._intervals.move_to_end(target)
        if event == ATTEMPT:
            cur.attempts += 1
            if flow.src_ip in cur.sources or len(cur.sources) < self.cfg.max_sources_per_target:
                cur.sources[flow.src_ip] += 1
            else:
                cur.sources_overflow += 1
        elif event == ANSWERED:
            cur.answered += 1
        elif event == REJECTED:
            cur.rejected += 1
        elif event == ESTABLISHED:
            cur.established += 1
        return ()

    def _close_interval(self, target: Target, iv: _Interval) -> None:
        """Evaluate a finished interval and fold it into the target's incident."""
        suspicious = (
            iv.attempts >= self.cfg.min_attempts and iv.established <= self.cfg.max_completion_ratio * iv.attempts
        )
        if not suspicious:
            return
        end = iv.start + self.cfg.interval_seconds
        inc = self._incidents.get(target)
        if inc is None:
            inc = self._incidents[target] = _Incident(target=target, first_seen=iv.start, last_seen=end)
            if self.early_warning:
                self._opened.append(target)
        inc.last_seen = end
        inc.attempts += iv.attempts
        inc.answered += iv.answered
        inc.rejected += iv.rejected
        inc.established += iv.established
        inc.intervals += 1
        inc.peak_attempts = max(inc.peak_attempts, iv.attempts)
        inc.sources_overflow += iv.sources_overflow
        for src, n in iv.sources.items():
            if src in inc.sources or len(inc.sources) < self.cfg.max_sources_per_target:
                inc.sources[src] += n
            else:
                inc.sources_overflow += n

    def tick(self, now: float) -> Iterable[Alert]:
        # Intervals are kept in update order, so ended ones are at the front.
        slot = self._slot(now)
        while self._intervals:
            target, iv = next(iter(self._intervals.items()))
            if iv.start >= slot:
                break
            del self._intervals[target]
            self._close_interval(target, iv)
        opened, self._opened = self._opened, []
        early = as_early(self._alert(self._incidents[t]) for t in opened if t in self._incidents)
        done = [
            t
            for t, inc in self._incidents.items()
            if now - inc.last_seen > self.cfg.idle_timeout_seconds or now - inc.first_seen > self.max_age
        ]
        return early + [self._alert(self._incidents.pop(t)) for t in done]

    def flush(self) -> Iterable[Alert]:
        for target, iv in list(self._intervals.items()):
            self._close_interval(target, iv)
        self._intervals.clear()
        alerts = [self._alert(inc) for inc in self._incidents.values()]
        self._incidents.clear()
        return alerts

    def _alert(self, inc: _Incident) -> Alert:
        ip, port = inc.target
        duration = inc.last_seen - inc.first_seen
        completion = inc.established / inc.attempts if inc.attempts else 0.0
        answer = inc.answered / inc.attempts if inc.attempts else 0.0
        distinct = len(inc.sources)
        distinct_text = f"{distinct:,}{'+' if inc.sources_overflow else ''}"
        single = sum(1 for n in inc.sources.values() if n == 1)
        severity = Severity.HIGH if inc.attempts >= self.cfg.high_severity_attempts else Severity.MEDIUM

        summary = (
            f"{ip}:{port} received {inc.attempts:,} new TCP connection attempts in {duration:.0f}s "
            f"(peak {inc.peak_attempts:,} per {self.cfg.interval_seconds:g}s) from {distinct_text} source IPs; "
            f"only {completion:.1%} completed the handshake (threshold: >= {self.cfg.min_attempts} attempts per "
            f"{self.cfg.interval_seconds:g}s with <= {self.cfg.max_completion_ratio:.0%} completed). "
            f"The target answered {answer:.0%} with SYN-ACK and {inc.rejected:,} with RST."
        )
        if distinct >= 100 and single >= 0.9 * distinct:
            summary += " Most sources sent a single attempt, which suggests spoofed source addresses or a botnet."
        elif distinct <= 3:
            summary += " The attempts come from very few sources (a flooding tool without source randomisation)."
        if answer < 0.1:
            summary += " The target barely answered: it may already be overloaded, filtered, or down."

        return Alert(
            detector=self.name,
            rule_id=RULE_ID,
            title=self.rules[0].title,
            severity=severity,
            first_seen=inc.first_seen,
            last_seen=inc.last_seen,
            src=None,
            dst=ip,
            technique=T1499_001,
            summary=summary,
            evidence={
                "target_port": port,
                "attempts": inc.attempts,
                "answered": inc.answered,
                "rejected": inc.rejected,
                "established": inc.established,
                "completion_ratio": round(completion, 4),
                "answer_ratio": round(answer, 4),
                "suspicious_intervals": inc.intervals,
                "peak_attempts_per_interval": inc.peak_attempts,
                "attempts_per_second": round(inc.attempts / duration, 1) if duration > 0 else None,
                "distinct_sources": distinct,
                "distinct_sources_capped": bool(inc.sources_overflow),
                "single_attempt_sources": single,
                "top_sources": [{"ip": s, "attempts": n} for s, n in inc.sources.most_common(10)],
                "threshold": {
                    "min_attempts": self.cfg.min_attempts,
                    "interval_seconds": self.cfg.interval_seconds,
                    "max_completion_ratio": self.cfg.max_completion_ratio,
                },
            },
        )
