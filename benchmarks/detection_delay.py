"""Time to detect: how long after an attack starts does its first alert appear?

Every attack scenario is run through the engine as a live session would see it:
early warnings on, and the capture clock ticking every second even when no
packet arrives (engine.advance), as `netguard monitor` does. For each expected
rule, the delay is first alert's reported_at minus the incident's first_seen.

    uv run python benchmarks/detection_delay.py
"""

from __future__ import annotations

from netguard.config import AlertsConfig
from netguard.detectors import DETECTORS
from netguard.engine import Engine
from netguard.lab.evaluate import entity
from netguard.lab.scenarios import SCENARIOS
from netguard.lab.synth import Frame

RULES = {d.name: d.rules[0].rule_id for d in DETECTORS}


def run(frames: list[Frame], engine: Engine) -> None:
    clock: float | None = None
    for ts, buf in sorted(frames, key=lambda f: f[0]):
        while clock is not None and clock + 1 < ts:  # silence between packets: tick every second
            clock += 1
            engine.advance(clock)
        engine.process_frame(ts, buf, 1)
        clock = ts if clock is None or ts > clock else clock
    for _ in range(120):  # silence after the capture
        assert clock is not None
        clock += 1
        engine.advance(clock)
    engine.finish()


def main() -> None:
    print("| Scenario | Rule | Entity | Detected after | First alert | Traffic duration |")
    print("|---|---|---|---:|---|---:|")
    for sc in SCENARIOS:
        if sc.kind != "attack":
            continue
        config = sc.config()
        config.alerts = AlertsConfig(early_warning=True)
        engine = Engine(config)
        frames = sc.build()
        run(frames, engine)
        span = max(t for t, _ in frames) - min(t for t, _ in frames)
        first: dict[tuple[str, str], tuple[float, str]] = {}
        for a in engine.alerts:
            key = entity(a)
            if key in sc.expected and a.reported_at is not None and key not in first:
                first[key] = (a.reported_at - a.first_seen, a.stage)
        for detector, ent in sorted(sc.expected):
            hit = first.get((detector, ent))
            rule = RULES[detector]
            cell = f"{hit[0]:.1f} s" if hit else "not detected"
            print(f"| `{sc.name}` | {rule} | `{ent}` | {cell} | {hit[1] if hit else '-'} | {span:.1f} s |")


if __name__ == "__main__":
    main()
