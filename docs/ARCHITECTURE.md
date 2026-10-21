# Architecture

## Goals and non-goals

**Goals:** explainable detections, a low false-positive rate, reproducible
measurements, easy extension with new detectors, and enough speed for home and
lab networks or offline analysis on a 4 GB VM.

**Non-goals (for now):** line-rate capture on 10 Gbit links, inline blocking
(IPS), and full protocol dissection. Zeek and Suricata already do those well.
NetGuard aims to be small, readable and explainable, and can later consume
their logs as additional inputs.

## Pipeline

```mermaid
sequenceDiagram
    participant S as sources.iter_frames
    participant E as Engine
    participant D as decode()
    participant T as TrafficStats
    participant X as Detector[]
    participant O as output

    S->>E: (ts, bytes, linktype)
    E->>D: decode
    D-->>E: Packet | None (decode error counted)
    E->>X: tick(ts)  [≤ once per capture-second, BEFORE the packet]
    X-->>E: alerts for incidents that went idle
    E->>T: add(packet)
    E->>X: on_packet(packet)
    Note over E,X: end of input
    E->>X: flush()
    E->>O: AnalysisResult(stats, alerts)
```

| Module | Responsibility | Key types |
|---|---|---|
| `sources.py` | Detect pcap vs pcapng from the magic number. Stream frames, stdin included. | `iter_frames`, `open_capture` |
| `decode.py` | Turn link-layer bytes into a flat, immutable `Packet`. Never raise on malformed input. | `decode`, `Packet` |
| `window.py` | Sliding-window distinct counting and incident aggregation. Shared by the scan detectors. | `SlidingDistinct`, `BurstTracker`, `Incident` |
| `detectors/` | One file per detection. Each one is a pure state machine with no I/O and no wall clock. | `Detector` ABC |
| `engine.py` | Order of operations, capture-time ticking, alert fan-out | `Engine`, `AnalysisResult` |
| `stats.py` | Counters, top talkers, bidirectional flow table with idle expiry | `TrafficStats`, `Flow` |
| `config.py` | Typed TOML config that rejects unknown keys, plus the allowlist | `Config` |
| `output.py` | Text, JSON and JSONL rendering | |
| `lab/` | Frame builders, labelled scenarios, evaluation harness | `Scenario`, `run_all` |

## Design principles

1. **Detectors are pure.** A detector receives `Packet` objects and returns
   `Alert` objects. It does no I/O and never reads the wall clock. This makes
   every detector testable with a few hand-built packets (`tests/helpers.py`).
2. **Capture time, not wall-clock time.** A pcap analysed today and the same
   traffic analysed live produce the same alerts.
3. **Incidents, not events.** Threshold crossings open an *incident*. The
   incident keeps collecting evidence, including replies that arrive after the
   last probe, and becomes exactly one alert when it goes idle. This trades
   latency (`idle_timeout_seconds`, 10 s by default) for far better evidence
   and far less noise. See [ADR-0003](adr/0003-incident-aggregation.md).
4. **Bounded memory everywhere.** An attacker controls the input, so they also
   control how much state we create. Every map and window has a cap. When a
   cap is hit, we deliberately fail *open* (we may miss something), we count it
   (`dropped_keys`, `flows_dropped`), and we never crash.
5. **Explainability is a feature.** The text of `summary` is part of the
   contract and is covered by tests.

## Adding a detector

1. Create `src/netguard/detectors/<name>.py` with a subclass of `Detector`.
   Implement `on_packet`, and also `tick`/`flush` if it aggregates.
2. Add a config dataclass in `config.py` and register it in `_SECTIONS`.
3. Register the detector in `detectors/__init__.py::build_detectors`.
4. Add unit tests built from `Packet` objects, plus at least one attack
   scenario and one *benign look-alike* scenario in `lab/scenarios.py`.
5. Update `tests/test_scenarios.py`, regenerate the table in
   `docs/EVALUATION.md`, and add the detector to the README.

## Data model

`Alert` is the stable external contract (JSON keys):

```json
{
  "detector": "portscan",
  "title": "TCP port scan",
  "severity": "HIGH",
  "first_seen": "2025-10-09T08:53:20.000+00:00",
  "last_seen": "2025-10-09T08:53:20.999+00:00",
  "src": "10.0.0.66",
  "dst": "10.0.0.10",
  "summary": "10.0.0.66 probed 1000 distinct TCP ports on 10.0.0.10 in 1.0s (...)",
  "technique": {"id": "T1046", "name": "Network Service Discovery", "url": "https://attack.mitre.org/techniques/T1046/"},
  "evidence": {"distinct_ports": 1000, "open_ports": [22, 80, 443], "...": "..."}
}
```

A future version may map these fields to the Elastic Common Schema (ECS) for
direct SIEM ingestion. See the [roadmap](../ROADMAP.md).
