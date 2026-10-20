"""Run every scenario through the full pipeline and score it against ground truth.

Metrics are computed on *entities* (see ``scenarios.py``): a true positive is an
expected (detector, entity) pair that produced at least one alert; a false
positive is an alerted pair that was not expected; a false negative is an
expected pair without an alert. Raw alert counts are reported separately so
alert *volume* (noise) is visible too.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory

from netguard.engine import analyze_frames
from netguard.lab.scenarios import SCENARIOS, Scenario
from netguard.lab.synth import write_pcap
from netguard.models import Alert
from netguard.sources import open_capture


def entity(alert: Alert) -> tuple[str, str]:
    if alert.detector == "portscan":
        return alert.detector, f"{alert.src}->{alert.dst}"
    if alert.detector == "arpspoof":
        return alert.detector, str(alert.dst)
    return alert.detector, str(alert.src)


@dataclass
class ScenarioResult:
    scenario: Scenario
    packets: int
    alerts: list[Alert]
    tp: set[tuple[str, str]] = field(default_factory=set)
    fp: set[tuple[str, str]] = field(default_factory=set)
    fn: set[tuple[str, str]] = field(default_factory=set)
    seconds: float = 0.0


def run_scenario(sc: Scenario, workdir: Path) -> ScenarioResult:
    pcap = workdir / f"{sc.name}.pcap"
    packets = write_pcap(pcap, sc.build())
    start = time.perf_counter()
    with open_capture(pcap) as frames:
        result = analyze_frames(frames, sc.config())
    elapsed = time.perf_counter() - start
    got = {entity(a) for a in result.alerts}
    return ScenarioResult(
        scenario=sc,
        packets=packets,
        alerts=result.alerts,
        tp=got & sc.expected,
        fp=got - sc.expected,
        fn=sc.expected - got,
        seconds=elapsed,
    )


def run_all() -> list[ScenarioResult]:
    with TemporaryDirectory() as tmp:
        return [run_scenario(sc, Path(tmp)) for sc in SCENARIOS]


def render_markdown(results: list[ScenarioResult]) -> str:
    lines = [
        "| Scenario | Type | Packets | Alerts | TP | FP | FN | Outcome | Note |",
        "|---|---|---:|---:|---:|---:|---:|---|---|",
    ]
    for r in results:
        if r.fn:
            outcome = "missed"
        elif r.fp:
            outcome = "false positive"
        elif r.tp:
            outcome = "detected"
        else:
            outcome = "quiet (correct)"
        lines.append(
            f"| `{r.scenario.name}` | {r.scenario.kind} | {r.packets} | {len(r.alerts)} | "
            f"{len(r.tp)} | {len(r.fp)} | {len(r.fn)} | {outcome} | {r.scenario.note} |"
        )
    tp = sum(len(r.tp) for r in results)
    fp = sum(len(r.fp) for r in results)
    fn = sum(len(r.fn) for r in results)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    lines += [
        "",
        f"**Totals:** TP={tp}, FP={fp}, FN={fn} — "
        f"precision {precision:.2f}, recall {recall:.2f} (entity level, synthetic scenarios).",
    ]
    return "\n".join(lines)
