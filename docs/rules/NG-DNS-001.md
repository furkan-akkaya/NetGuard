# NG-DNS-001 — Possible DNS tunnelling

- **Detector:** `dnstunnel` · **ATT&CK:** [T1071.004 Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/) (also relevant: T1048 exfiltration over alternative protocol)

## What it detects

A client sending a stream of long, unique subdomains under one registered
domain, the footprint of data encoded in DNS names: iodine, dnscat2,
DNSExfiltrator, DNS C2 beacons.

## Signal

Per `(client, registered domain)` in a sliding window: distinct subdomains ≥
`min_distinct_subdomains` opens an incident; it is reported only if the mean
subdomain length is ≥ `min_mean_subdomain_length`. Severity is HIGH with ≥
`high_severity_subdomains` subdomains or when ≥ 50% of queries use TXT, NULL,
CNAME or MX (record types tunnels prefer for downstream data).

The registered domain is approximated with a small built-in list of
second-level labels (`co.uk`, `com.tr`, …) instead of the Public Suffix List.

| Setting (`[dnstunnel]`) | Default |
|---|---:|
| `window_seconds` | 300 |
| `min_distinct_subdomains` | 50 |
| `min_mean_subdomain_length` | 24 |
| `idle_timeout_seconds` | 60 |
| `high_severity_subdomains` | 500 |

## Evidence

`registered_domain`, `distinct_subdomains`, `queries`,
`mean_subdomain_length`, `longest_label`, `mean_entropy_bits_per_char`,
`query_types`, `tunnel_record_type_share`, `sample_names`, `threshold`.

## Known false positives

Security and telemetry products that encode lookups in names (antivirus file
reputation, some CDN/ad-tech tracking, DNS-based blocklists such as
`*.zen.spamhaus.org` queried by mail servers). Allowlist those clients or tune
per domain once seen.

## Known false negatives

Slow tunnels below the distinct-subdomain threshold in the window, tunnels
with short labels, DNS over HTTPS/TLS (encrypted, invisible to this rule),
and tunnels spreading across many registered domains.
