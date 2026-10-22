# NG-FRAG-001 — Suspicious IP fragmentation (possible IDS evasion)

- **Detector:** `fragments` · **ATT&CK:** [T1599 Network Boundary Bridging](https://attack.mitre.org/techniques/T1599/) (closest match; the technique is filter/IDS evasion)
- **Reference:** RFC 1858, *Security Considerations for IP Fragment Filtering*.

## What it detects

Fragments built to hide transport headers from packet filters and IDSs:
`nmap -f` / `--mtu`, fragroute, hping3 `-f`.

## Signal

Per IPv4 fragment, one of:

| Kind | Condition |
|---|---|
| `tiny_first_fragment` | first fragment (offset 0, MF set) of TCP/UDP too short to hold the transport header |
| `tcp_header_split` | TCP fragment starting at offset 8: the TCP header is split, or overwritten if it overlaps (RFC 1858) |
| `small_fragment` | any non-final fragment with less than `small_fragment_bytes` of payload |

Suspicious fragments are counted per `(source, target)`; at least
`min_fragments` within an activity burst (ended by `idle_timeout_seconds` of
quiet) produce one alert.

| Setting (`[fragments]`) | Default |
|---|---:|
| `small_fragment_bytes` | 256 |
| `min_fragments` | 5 |
| `idle_timeout_seconds` | 30 |
| `high_severity_fragments` | 100 |
| `max_keys` | 10 000 |

## Evidence

`suspicious_fragments`, `kinds`, `protocols`, `smallest_fragment_payload_bytes`, `threshold`.

## Limitations

NetGuard does not reassemble fragments, so the probes inside them are not seen
by the scan rules; this rule reports the evasion attempt instead. IPv6
fragments are not inspected yet. Overlapping fragments with *different* data
(Teardrop-style or Ptacek–Newsham evasion) are only caught when they match one
of the kinds above.

## Known false positives

Networks with a very small MTU on some path (rare; some tunnels and satellite
links), and fragmentation by middleboxes that re-fragment badly.
