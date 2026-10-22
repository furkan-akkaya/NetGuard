# ADR-0006: Connection events and outcome-aware scan detection

- **Status:** Accepted
- **Date:** 2026-10-22

## Context

Phase 3 adds detections that depend on *how connections turn out*: SYN floods
(handshakes that never complete), TRW scan detection (first contacts that
fail), UDP scans (who originated a UDP flow). Two simpler designs were
available and rejected:

- **Detectors inspect raw packets only.** Each detector would rebuild its own
  partial flow state (pending SYNs, who sent first), duplicating the flow
  table and its memory bounds, and getting edge cases (retransmitted SYNs,
  port reuse, orientation) subtly different.
- **Detectors use finished flows only (`on_flow_end`).** Correct, but an
  unanswered SYN only becomes a finished `S0` flow after the 30 s handshake
  timeout, and an established connection only finishes when it closes. A SYN
  flood would be reported tens of seconds late.

## Decision

1. The flow table reports a **connection event** at the packet that causes a
   handshake transition, once per flow: `attempt` (originator's SYN opens a
   flow; for UDP: the originator's first datagram), `answered` (first
   SYN-ACK; UDP: first reply), `rejected` (RST before any SYN-ACK),
   `established` (originator's first ACK after the SYN-ACK). Detectors
   implement `on_conn_event(event, flow, ts)`; the engine only calls detectors
   that override it.
2. Unanswered attempts still come from `on_flow_end` (`S0` with
   `end_reason="idle"`); `eof` and `evicted` endings are *unknown* outcomes,
   never failures.
3. **Two scan rules on purpose:** the window rule (NG-SCAN-001) reports fast
   and covers non-SYN probes (NULL/FIN/XMAS); TRW (NG-SCAN-002) uses outcomes,
   has no time window (catches slow scans) and lowers suspicion on successful
   connections. The window rule also became outcome-aware: an incident in which
   more than `max_open_ratio` of the ports were open is not reported.
4. **Protocol dispatch:** detectors declare `packet_protos`; the engine calls
   `on_packet` only for matching protocols and only calls `_emit` when a hook
   returned alerts. With 11 rules this cut per-packet engine overhead enough to
   stay within the 20% performance budget (reference capture 2.2 s → 2.45 s).

## Measured on the synthetic scenarios

| Scenario | v0.2 (window rule only) | v0.3 |
|---|---|---|
| `passive_ftp` (benign) | false positive | quiet: suppressed by `max_open_ratio`, TRW sees 26 successes |
| `slow_scan` (1 probe / 15 s) | missed | detected by TRW after 6 outcomes |
| `syn_scan_1000` | detected | detected by both rules |
| `xmas_scan` | detected | detected by the window rule only (no SYN, no attempt event) |

## Consequences

- Overlapping alerts are expected (a SYN scan raises NG-SCAN-001 and
  NG-SCAN-002). Correlating them into one incident is Phase 7 work.
- TRW's per-source state (~0.3 KB) is bounded by `max_sources` (LRU) and
  `state_timeout_seconds`, which is also its slow-scan horizon.
- The `max_open_ratio` suppression means a scan of a host where nearly every
  probed port is open goes unreported by the window rule; TRW would also
  stay quiet. This is documented in the rule pages.
