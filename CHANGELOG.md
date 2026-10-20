# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [0.1.0] - 2026-10-20

### Added
- pcap/pcapng reader for files and non-seekable streams (`tcpdump -w - | netguard analyze -`).
- Hardened decoder for Ethernet, Linux SLL, BSD loopback, raw IP; IPv4/IPv6; TCP, UDP, ICMP, ICMPv6, ARP; DNS query names.
- Sliding-window distinct counter and incident aggregation (`window.py`).
- Detectors: `portscan` (SYN/NULL/FIN/XMAS, open/closed port evidence), `hostsweep` (ICMP/ARP/TCP, alive hosts), `arpspoof` (binding changes with suspect attribution and escalation).
- MITRE ATT&CK mapping, text/JSON/JSONL output, TOML configuration with allowlist.
- Lab: 11 labelled synthetic scenarios, `netguard lab generate|list|evaluate`, scorecard locked by tests.
- CI (ruff, mypy --strict, pytest on Linux/macOS × Python 3.11–3.13).
