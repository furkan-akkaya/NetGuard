# NG-ARP-001 — ARP binding change (possible ARP spoofing)

- **Detector:** `arpspoof` · **ATT&CK:** [T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning](https://attack.mitre.org/techniques/T1557/002/)
- **Confidence wording:** "possible ARP spoofing". A binding change is suspicious, not proof.

## What it detects

An IP address whose ARP binding (IP → MAC) changes to a different MAC, the
observable effect of ARP cache poisoning (`arpspoof`, `bettercap arp.spoof`,
Ettercap).

## Signal

The detector learns IP → MAC bindings from ARP requests and replies. A known
IP announced from a different MAC raises an alert. Context that raises
suspicion and severity:

- **unsolicited reply** — nobody asked for that IP recently;
- **flip-flopping** — the binding alternates between MACs (the real owner and
  the attacker keep overwriting each other) → HIGH;
- **critical IP** — the IP is in `critical_ips`, e.g. the default gateway → HIGH.

The suspect MAC is the one that took over a binding with an established owner.

| Setting (`[arpspoof]`) | Default | Meaning |
|---|---:|---|
| `realert_seconds` | 300 | Do not repeat an alert for the same IP at the same or lower severity within this time |
| `critical_ips` | `[]` | IPs whose takeover is always HIGH |

## Evidence

`ip`, `previous_mac`, `new_mac`, `original_mac`, `suspect_mac`,
`previous_binding_age_seconds`, `binding_changes`, `macs_seen`,
`unsolicited_reply`, `gratuitous`, `critical_ip`, `arp_op`.

## Known false positives

- **DHCP re-assignment** of an IP to a new device (`dhcp_reassignment`).
- **First-hop redundancy failover** (VRRP/HSRP/CARP), NIC replacement, VM
  migration. These usually change the binding once and do not flip back.

## Known false negatives

Poisoning that targets only the victim's cache with replies the sensor cannot
see (switched networks without a mirror port); attackers that spoof before the
sensor has learned the real binding.

## Tuning

Put the gateway and other infrastructure IPs in `critical_ips`. Correlating
with DHCP leases (planned) is the real fix for the DHCP false positive.
