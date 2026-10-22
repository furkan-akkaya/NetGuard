# NG-DNS-002 — Burst of failed DNS lookups (possible DGA)

- **Detector:** `nxdomain` · **ATT&CK:** [T1568.002 Dynamic Resolution: Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002/)

## What it detects

A client receiving NXDOMAIN for many distinct names within a short time, as
malware with a domain generation algorithm does while it searches for its
registered C2 domain (Conficker, Necurs, many loaders).

## Signal

Resolver *responses* with `rcode = NXDOMAIN`, keyed by the client they are
sent to: distinct query names ≥ `min_distinct_names` within the window.

| Setting (`[nxdomain]`) | Default |
|---|---:|
| `window_seconds` | 60 |
| `min_distinct_names` | 25 |
| `idle_timeout_seconds` | 30 |
| `high_severity_names` | 200 |

## Evidence

`distinct_names`, `responses`, `registered_domains`, `domain_spread`
(registered domains ÷ names), `mean_label_length`,
`mean_entropy_bits_per_char` (of the leftmost label), `resolvers`,
`sample_names`, `threshold`. The summary says whether the names spread over
many domains (DGA-like) or share one or two (search-suffix-like).

## Known false positives

- **Wrong DNS search suffix** (`search_suffix_nxdomain` scenario, measured FP):
  every short name is first tried under the suffix and fails. Evidence: one
  registered domain, readable labels.
- Ad/tracker blockers answering NXDOMAIN on purpose; broken software retrying
  variants; Chrome's intranet-redirect probes (three random names at start-up,
  below the threshold).

## Known false negatives

DGAs with few candidates per day, DGAs whose domains are mostly *registered*
(sinkholes answer NOERROR), and clients whose resolver traffic the sensor
cannot see.
