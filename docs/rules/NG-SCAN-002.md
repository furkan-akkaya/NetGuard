# NG-SCAN-002 — Scan detected by connection outcomes (TRW)

- **Detector:** `trw` · **ATT&CK:** [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- **Method:** Threshold Random Walk, Jung et al., *Fast Portscan Detection Using Sequential Hypothesis Testing*, IEEE S&P 2004.

## What it detects

A source whose *first-contact* TCP connection attempts mostly fail: SYN and
connect scans (`nmap -sS/-sT`), horizontal and vertical, **including slow
scans** that stay under any rate threshold (`nmap -T1`, one probe per 15 s).

## Signal

Each new `(destination, port)` a source tries is a trial. Its outcome comes
from the flow table's connection events:

| Outcome | Evidence | Effect on Λ |
|---|---|---|
| success | SYN-ACK from the responder | `ln(θ₁/θ₀)` ≈ −1.39 |
| failure: rejected | RST before any SYN-ACK | `ln((1−θ₁)/(1−θ₀))` ≈ +1.39 |
| failure: unanswered | no reply before the 30 s handshake timeout | ≈ +1.39 |
| unknown | input ended or flow evicted before an answer | not counted |

Λ ≥ `ln(P_D/P_F)` (≈ 4.6) **and** at least `min_failures` failures → scanner.
Λ ≤ `ln((1−P_D)/(1−P_F))` → benign so far, the walk restarts. Repeated
attempts to the same `(destination, port)` are not first contacts and are ignored.

| Setting (`[trw]`) | Default | Meaning |
|---|---:|---|
| `benign_success_probability` (θ₀) | 0.8 | Chance a benign first contact succeeds |
| `scanner_success_probability` (θ₁) | 0.2 | Chance a scanner's probe succeeds |
| `detection_probability` (P_D) | 0.99 | Target detection probability of the test |
| `false_positive_probability` (P_F) | 0.01 | Target false-positive probability of the test |
| `min_failures` | 5 | Never decide on fewer failed first contacts |
| `idle_timeout_seconds` | 60 | Report a decided scanner after this long without new outcomes |
| `state_timeout_seconds` | 3600 | Forget an undecided source idle this long (slow-scan horizon) |
| `high_severity_failures` | 100 | Failures for HIGH severity |
| `max_sources`, `max_contacts_per_source` | 50 000, 4096 | Memory bounds (LRU) |

## Evidence

`first_contacts`, `outcomes`, `successes`, `failures`, `rejected`,
`unanswered`, `success_ratio`, `distinct_hosts`, `distinct_ports`,
`decided_after_outcomes`, `decided_at_seconds`, `log_likelihood_ratio`,
`sample_failed_targets`, `threshold`.

## Deviations from the paper

- Contacts are `(destination, port)` pairs, not hosts, so vertical scans of a
  single host are covered.
- `min_failures` is added because four consecutive failed first contacts is
  common in real networks (a client trying dead services).
- Unanswered attempts are only failures after the handshake timeout; a capture
  that ends mid-handshake does not count as failure.

## Known false positives

P2P clients (BitTorrent peer lists are full of dead peers), software probing
many stale addresses, a host whose network path is broken. Allowlist known
scanners and monitoring systems.

## Known false negatives

Stealth scans without SYN (NULL/FIN/XMAS: no connection attempt, see NG-SCAN-001),
UDP scans (NG-SCAN-003), scans spread across spoofed decoy sources, and scans of
ranges where most ports are open (rare).

## Tuning

Lower `min_failures` for faster decisions on quiet networks; raise
`state_timeout_seconds` to catch slower scans at the cost of memory
(~0.3 KB per tracked source).
