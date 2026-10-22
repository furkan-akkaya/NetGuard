# ADR-0010: Live capture, replay and the alert lifecycle

- **Status:** Accepted (refines [ADR-0002](0002-capture-via-tcpdump.md) and [ADR-0003](0003-incident-aggregation.md))
- **Date:** 2026-10-22

## Context

Phase 6 adds controlled live capture, replay of recorded captures and live
alerting. Three problems are new compared with offline analysis:

1. **Privileges.** Opening a capture device needs root or a capture
   capability. NetGuard parses hostile bytes and must not run with them.
2. **Time.** Offline, the engine advances only when a packet arrives. Live,
   a scan that stops is followed by silence: with no next packet, its
   incident would never close and the alert would never be reported.
3. **Latency.** Incidents are reported once they go idle (ADR-0003): good
   evidence, but a live analyst learns about a running scan only after it
   stops, and a scan that never stops is never reported.

## Decisions

### Capture stays in tcpdump; NetGuard refuses to run as root

`netguard monitor -i IFACE` starts `tcpdump -i IFACE -U -n -w - -s SNAPLEN
[-c N] [FILTER]` as a child process (argument vector, no shell) and parses its
stdout. The interface must be named explicitly (no default, no `any`), the
name is validated, and the BPF filter is passed as one argument. NetGuard
exits with guidance if it is itself running as root. Capture permission is
granted to tcpdump instead:

| Platform | Unprivileged option | Fallback |
|---|---|---|
| Linux | `setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)` | `--sudo` → `sudo -n tcpdump … -Z <user>` |
| macOS | BPF device access (Wireshark's ChmodBPF / `access_bpf` group) | `--sudo` as above |

With `--sudo`, tcpdump drops to the invoking user (`-Z`) right after opening
the device, so not even tcpdump keeps root while handling traffic.
Starting captures from the web dashboard is deliberately **not** offered: it
would make the network-facing API process able to spawn privileged capture.

### A reader thread, a bounded queue and a clock

A source thread (tcpdump, or a paced file reader for replay) decodes frames
and puts them on a bounded queue. The main thread runs the engine alone (the
engine stays single-threaded) and, when the queue is empty for a second,
advances the engine clock with `Engine.advance(now)`. The clock is the
capture clock: at the first packet the offset between packet timestamps and
the monotonic clock is recorded, so replayed old captures and live traffic
behave the same. When the queue is full the reader blocks, back-pressure
reaches tcpdump and the kernel, and drops are reported from tcpdump's own
statistics (`packets dropped by kernel`) instead of growing memory.

### Alert lifecycle: early warning, final, maximum age

Alert contract 1.1 adds two fields (minor version: additive):

- `stage`: `"early"` when an incident has just crossed its threshold and is
  still open (evidence incomplete), `"final"` when it closed. Both share the
  same deterministic `alert_id`, so a consumer keeps the latest per id.
- `reported_at`: the capture-clock time at which the alert was emitted.
  `reported_at - first_seen` is the detection delay.

`[alerts] early_warning` (off for offline analysis, on for `monitor` and
`replay`) and `[alerts] max_incident_age_seconds` (default 3600): an incident
older than this is closed and reported even if activity continues; continued
activity opens a new incident.

### Replay

`netguard replay CAPTURE --speed N` feeds a recorded capture through the live
pipeline at N× its original pace (`--speed 0` = as fast as possible). Because
every component runs on the capture clock, the final alerts of a replay equal
those of `netguard analyze` on the same file, which a test asserts. Injecting
packets onto a network (`tcpreplay`) is left to the lab: it needs root and
belongs on an isolated network.

## Consequences

- Live verification on a real interface needs a host with capture permission
  (the lab); CI and unit tests use a scripted capture source and the real
  tcpdump permission-denied path.
- Early warnings can be revised or withdrawn: a window-based incident that is
  later suppressed (e.g. mostly open ports) produces an early alert without a
  final one. Consumers must treat `early` as provisional.
