# ADR-0004: Flow identity, connection state and flow lifetime

- **Status:** Accepted
- **Date:** 2026-10-22

## Context

Phase 2 moves NetGuard from packets to connections. The next detectors need
flow facts: did the handshake complete (TRW scan detection), how many SYNs
never got an answer (SYN flood), how many bytes went each way (exfiltration),
how regular are connection starts (beaconing). The v0.1 flow table only
counted packets and bytes per 5-tuple, and silently *dropped* new flows when it
was full.

Questions this ADR answers: what is one flow, who is its originator, what
state is it in, when does it end, and what happens when memory runs out.

## Decisions

### 1. Identity: bidirectional 5-tuple, originator = first sender

A flow is all packets with the same `(proto, {ip_a:port_a, ip_b:port_b})` in
either direction. The canonical key sorts the two endpoints, so `A→B` and
`B→A` hit the same entry in O(1). The sender of the first packet is the
**originator** (`src_*` fields), with one exception: if the first TCP packet is
a SYN-ACK, we missed the SYN and the orientation is flipped.

ICMP and other port-less protocols use port 0, so all ICMP between two hosts
is one flow. Non-first IP fragments have no L4 header and are not assigned to
any flow (counted in statistics only). ARP is not IP and has no flow.

*Rejected:* Zeek's port-based heuristics for orientation (e.g. "the lower,
well-known port is the responder"). They fix mid-stream captures but are wrong
for peer-to-peer and high-port services; the SYN/SYN-ACK rule is exact when
the handshake is visible and the limitation is documented when it is not.

### 2. State: Zeek `conn_state` vocabulary, derived from flags per direction

We report Zeek's states (`S0, S1, SF, REJ, S2, S3, RSTO, RSTR, RSTOS0, RSTRH,
SH, SHR, OTH`) so results can be compared one-to-one with `conn.log`. The state
is computed from the OR of TCP flags seen in each direction, with this
precedence:

1. Originator SYN, no responder SYN → `REJ` (responder RST) › `RSTOS0`
   (originator RST) › `SH` (originator FIN) › `S0`.
2. Responder SYN, no originator SYN → `RSTRH` › `SHR` › `OTH`.
3. No SYN at all → `OTH` (mid-stream).
4. Both SYNs (established) → `RSTO` › `RSTR` › `SF` (FIN both ways) › `S2`
   (originator FIN only) › `S3` (responder FIN only) › `S1`.

UDP/ICMP flows are `SF` if the responder sent anything, otherwise `S0`.

*Rejected:* a full RFC 9293 state machine. A passive observer cannot know
which segments the endpoints actually received, so tracking `SYN-RECEIVED`,
`TIME-WAIT` etc. would claim precision we do not have. Flag accumulation is
O(1), order-insensitive (robust to small reordering) and sufficient for every
planned detector.

### 3. Sequence analysis: retransmissions and gaps, honestly named

For data, SYN and FIN segments we keep the highest sequence end seen per
direction (32-bit serial arithmetic, RFC 1982, so wrap-around is handled). A
segment that does not extend it counts as a `retransmission`; one that starts
beyond it counts as a `seq_gap`. An observer cannot distinguish a
retransmission from a late out-of-order arrival, so both are counted together
and the docstring says so. TCP keep-alives count as retransmissions, as in
Zeek. Payload length comes from the IP length field, so a short snaplen does
not create false gaps.

### 4. Lifetime: timeout classes and an O(1) expiry structure

A flow ends when it is closed, idle, evicted, or the input ends
(`end_reason` = `closed | idle | evicted | eof`). Idle timeouts depend on state:

| Class | Default | Zeek equivalent |
|---|---:|---|
| TCP with no reply yet (half-open) | 30 s | `tcp_attempt_delay` (5 s), longer to absorb SYN retries |
| TCP with replies | 300 s | `tcp_inactivity_timeout` (5 min) |
| TCP closed (FIN both ways, or RST) | 5 s linger | `tcp_close_delay` / `tcp_reset_delay` (5 s) |
| UDP | 60 s | `udp_inactivity_timeout` (1 min) |
| Other (ICMP, …) | 60 s | `icmp_inactivity_timeout` (1 min) |

A SYN on a closed 5-tuple ends the old flow immediately (port reuse).

Each class is an `OrderedDict` in least-recently-updated order. Because all
flows in one class share one timeout, the front of each list is always the
next to expire: `expire()` pops from the front and stops at the first live
flow. That is amortized O(1) per flow, instead of the O(active flows) scan per
tick that a single table needs. A flow that changes class (e.g. half-open →
established) moves between lists in O(1).

### 5. Memory bound: evict the least recently seen, and say so

`max_flows` (default 200 000) caps the table. When it is full, expired flows
are ended first; if none, the least recently seen flow overall is ended with
`end_reason="evicted"`, and the count is reported in the output.

*Rejected:* dropping the new flow (the v0.1 behaviour). A flood that fills the
table before an attack would then hide the attack's flows completely. Eviction
can end a real long-lived flow early (its record is split in two), which is
the lesser failure, and it is counted.

## Consequences

- Detectors get `on_flow_end(flow)`; flow records can be exported
  (`netguard flows`) and compared with Zeek.
- Memory per flow is ~0.3–0.5 KB; at the default cap the flow table is at most
  ~100 MB. The worst case is measured by `benchmarks/flood_memory.py`.
- Known limitations: mid-stream flows without a SYN keep the first sender as
  originator; simultaneous open is reported as an ordinary established flow;
  ICMP flows are not split by echo id; timestamps that go backwards are
  tolerated but slightly distort LRU order.
