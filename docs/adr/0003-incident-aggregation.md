# ADR-0003: Aggregate threshold crossings into incidents

- **Status:** Accepted
- **Date:** 2026-10-20

## Context

A naive threshold detector alerts every time a counter crosses its threshold,
or on every packet above it. One `nmap` run would then produce hundreds of
alerts, and analysts learn to ignore noisy tools (*alert fatigue*). Also, at
the moment the threshold is crossed, the most useful evidence (which ports
answered, how big the scan was) does not exist yet.

## Options considered

1. **Alert on crossing plus a cooldown.** Fast, but the evidence is incomplete
   and a long scan is either one under-described alert or several fragments.
2. **Incident aggregation (chosen).** The crossing opens an incident. The
   incident absorbs all further events and replies, and is emitted once it has
   been idle for `idle_timeout_seconds` or the input ends.
3. **Both:** an early-warning alert at crossing, then a final incident report.
   This is the best user experience but doubles the alert lifecycle complexity.
   It is planned for Phase 3, once alerts have IDs and states.

## Decision

Option 2, implemented generically in `window.BurstTracker`.

## Consequences

- One scan becomes one alert with complete evidence: total ports, open ports,
  probe types and rate.
- Live alerts are delayed by the idle timeout (10 s by default). A scan that
  never pauses is reported at end of input. Phase 3 adds a max-incident-age
  flush and early warnings.
- Evidence observed *before* the threshold (for example a SYN-ACK to the very
  first probe) is held in a per-key pending record and merged into the
  incident. A unit test covers this.
- Order of operations matters: the engine must expire idle incidents
  **before** processing the next packet. Otherwise that packet extends an
  incident that has already ended. A regression test covers this.

## Update (2026-10-22)

The roadmap was renumbered. The early-warning alert and max-incident-age work
referred to above as "Phase 3" is now task **6.4** (live capture phase).
Since v0.2.0 a closed incident also clears its key's window, so the events of
one incident can never re-open the next one (each event belongs to at most one
incident).
