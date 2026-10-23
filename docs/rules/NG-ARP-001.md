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
| `trust_dhcp` | `true` | Do not report a change that a DHCP ACK from a trusted server just assigned |
| `dhcp_servers` | `[]` | Trusted DHCP servers; empty = the first server seen (trust on first use) |
| `dhcp_window_seconds` | 3600 | How long after its ACK a lease explains a change |

### DHCP lease correlation (v0.7)

The detector also reads DHCP ACKs. When an IP moves to a new MAC that a DHCP
ACK from a **trusted** server assigned it to within `dhcp_window_seconds`, the
new device becomes the owner and no alert is raised (counted as
`explained_by_dhcp`). Safeguards: ACKs from any other server never explain a
change (a rogue DHCP server cannot launder spoofing — scenario
`arp_spoof_with_rogue_dhcp`), and a binding that has already changed (a fight
over the IP) is never explained. With trust on first use, a rogue server that
answers *before* the real one would become trusted; set `dhcp_servers`
explicitly on networks where that matters.

## Evidence

`ip`, `previous_mac`, `new_mac`, `original_mac`, `suspect_mac`,
`previous_binding_age_seconds`, `binding_changes`, `macs_seen`,
`unsolicited_reply`, `gratuitous`, `critical_ip`, `arp_op`.

## Known false positives

- **DHCP re-assignment** of an IP to a new device when the DHCP exchange is
  not visible to the sensor (`dhcp_reassignment`); with the ACK visible it is
  explained and not reported (`dhcp_reassignment_seen`).
- **First-hop redundancy failover** (VRRP/HSRP/CARP), NIC replacement, VM
  migration. These usually change the binding once and do not flip back.

## Known false negatives

Poisoning that targets only the victim's cache with replies the sensor cannot
see (switched networks without a mirror port); attackers that spoof before the
sensor has learned the real binding.

## Tuning

Put the gateway and other infrastructure IPs in `critical_ips`, and list your
DHCP servers in `dhcp_servers`. Place the sensor where DHCP traffic is visible
(e.g. on the uplink of the DHCP server) to benefit from lease correlation.
