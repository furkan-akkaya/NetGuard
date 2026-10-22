"""Labelled, synthetic traffic scenarios with ground truth.

Each scenario is small, deterministic and documents *what* it simulates. Benign
scenarios are just as important as attacks: they are how we measure false
positives. Some scenarios intentionally expose known weaknesses (slow scans,
DHCP re-assignment, passive FTP) so the limitations are measured, not hidden.

Ground truth is expressed as *entities*:

* ``portscan``, ``udpscan`` -> ``"scanner->target"``
* ``hostsweep``, ``trw``, ``dnstunnel``, ``nxdomain``, ``connrate``, ``volume`` -> ``"source"``
* ``synflood``  -> ``"target"``
* ``arpspoof``  -> ``"victim_ip"`` (the IP whose binding was hijacked)

An attack scenario counts as *detected* when at least one expected pair fired;
the per-pair TP/FN still shows which rules saw it.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass, field

from netguard.config import Config
from netguard.dns import RCODE_NXDOMAIN
from netguard.lab.synth import Frame, Host, bulk_transfer, dns_response, fragment, syn_probe, tcp_handshake
from netguard.models import ACK, FIN, PSH, SYN, URG

T0 = 1_760_000_000.0  # fixed epoch so every run is byte-for-byte reproducible

GATEWAY = Host("10.0.0.1", "02:00:00:00:00:01")
MONITOR = Host("10.0.0.5", "02:00:00:00:00:05")
SERVER = Host("10.0.0.10", "02:00:00:00:00:10")
WORKSTATION = Host("10.0.0.20", "02:00:00:00:00:20")
RESOLVER = Host("10.0.0.53", "02:00:00:00:00:53")
ATTACKER = Host("10.0.0.66", "02:00:00:00:00:66")
LAN_ALIVE = [GATEWAY, MONITOR, SERVER, WORKSTATION, RESOLVER]
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]


@dataclass
class Scenario:
    name: str
    kind: str  # "attack" or "benign"
    description: str
    build: Callable[[], list[Frame]]
    expected: set[tuple[str, str]] = field(default_factory=set)  # {(detector, entity)}
    config: Callable[[], Config] = Config
    note: str = ""


def _ports(n: int) -> list[int]:
    rest = [p for p in range(1, 65536) if p not in TOP_PORTS]
    return (TOP_PORTS + rest)[:n]


# --- benign -----------------------------------------------------------------


def benign_office() -> list[Frame]:
    """A workstation browsing the web and using internal services for 60s.

    Each public HTTPS server answers and the connection completes (until v0.2
    the synthetic browser's SYNs went unanswered, which no real browsing
    session looks like: forty failed connections in a row is an outage).
    """
    frames: list[Frame] = [
        (T0, WORKSTATION.arp_request(GATEWAY.ip)),
        (T0 + 0.001, GATEWAY.arp_reply(WORKSTATION)),
    ]
    t = T0 + 0.1
    for i in range(40):  # 40 different public web servers (CDNs, APIs, trackers)
        dst = f"93.184.{i // 10}.{10 + i}"
        sport = 50000 + i
        name = f"cdn{i}.example.com"
        frames.append((t, WORKSTATION.dns_query(RESOLVER, name, sport=sport, qid=i)))
        frames.append((t + 0.005, dns_response(RESOLVER, WORKSTATION, name, qid=i, dport=sport)))
        # Off-link server: frames reach the workstation from the gateway's MAC.
        frames += tcp_handshake(WORKSTATION, Host(dst, GATEWAY.mac), t + 0.01, sport, 443, data=1)
        t += 0.5
    for i, port in enumerate([445, 445, 80, 443, 3389]):
        frames += tcp_handshake(WORKSTATION, SERVER, T0 + 30 + i, 51000 + i, port)
    return frames


def monitoring_poller() -> list[Frame]:
    """A monitoring server pinging 30 internal hosts every 60s (like Nagios/Zabbix)."""
    frames: list[Frame] = []
    for cycle in range(3):
        for i in range(30):
            ip = f"10.0.1.{i + 1}"
            mac = f"02:00:00:00:01:{i + 1:02x}"
            ts = T0 + cycle * 60 + i * 0.05
            frames.append((ts, MONITOR.icmp_echo(ip, mac, seq=cycle)))
            frames.append((ts + 0.001, Host(ip, mac).icmp_echo(MONITOR.ip, MONITOR.mac, reply=True, seq=cycle)))
    return frames


def dhcp_reassignment() -> list[Frame]:
    """An IP is released and handed by DHCP to a different laptop two hours later."""
    old, new = Host("10.0.0.77", "02:00:00:00:aa:01"), Host("10.0.0.77", "02:00:00:00:bb:02")
    return [
        (T0, old.arp_reply(GATEWAY)),
        (T0 + 7200, new.arp_request(new.ip)),  # gratuitous ARP announcement (RFC 5227)
    ]


def passive_ftp() -> list[Frame]:
    """An FTP client downloading 25 files; each passive-mode transfer uses a new server port."""
    frames = tcp_handshake(WORKSTATION, SERVER, T0, 50000, 21, data=5)
    for i in range(25):
        frames += tcp_handshake(WORKSTATION, SERVER, T0 + 1 + i * 1.5, 50100 + i, 40000 + i * 7, data=2)
    return frames


def flash_crowd() -> list[Frame]:
    """800 different clients connect to one web server within 4s (a link goes viral); all succeed."""
    frames: list[Frame] = []
    for i in range(800):
        client = Host(f"172.16.{i // 250}.{i % 250 + 1}", f"02:00:00:02:{i // 250:02x}:{i % 250 + 1:02x}")
        frames += tcp_handshake(client, SERVER, T0 + i * 0.005, 40000 + i, 443, data=1)
    return frames


def voip_call() -> list[Frame]:
    """A softphone exchanging RTP media with a media server on 20 UDP port pairs; every port answers."""
    frames: list[Frame] = []
    for i in range(20):
        port = 16384 + 2 * i
        for k in range(5):
            ts = T0 + i * 0.5 + k * 0.02
            frames.append((ts, WORKSTATION.udp(SERVER, 20000 + 2 * i, port, b"\x80" * 160)))
            frames.append((ts + 0.01, SERVER.udp(WORKSTATION, port, 20000 + 2 * i, b"\x80" * 160)))
    return frames


def cdn_lookups() -> list[Frame]:
    """A browser resolving 80 short, distinct subdomains of one CDN domain (image and API shards)."""
    frames: list[Frame] = []
    for i in range(80):
        name = f"img{i}.static.cdnprovider.net"
        frames.append((T0 + i * 0.5, WORKSTATION.dns_query(RESOLVER, name, sport=40000 + i, qid=i)))
        frames.append((T0 + i * 0.5 + 0.01, dns_response(RESOLVER, WORKSTATION, name, qid=i, dport=40000 + i)))
    return frames


def search_suffix_nxdomain() -> list[Frame]:
    """A laptop with a wrong DNS search suffix: every short name is first tried under corp.example and fails."""
    words = ["intranet", "wiki", "mail", "files", "print", "jira", "git", "build", "hr", "vpn"]
    frames: list[Frame] = []
    for i in range(30):
        name = f"{words[i % len(words)]}{i // len(words) or ''}.corp.example"
        frames.append((T0 + i, WORKSTATION.dns_query(RESOLVER, name, sport=41000 + i, qid=100 + i)))
        frames.append((T0 + i + 0.01, dns_response(RESOLVER, WORKSTATION, name, 100 + i, RCODE_NXDOMAIN, 41000 + i)))
    return frames


def _steady_connections(host: Host, server: Host, minutes: int, per_minute: Callable[[int], int]) -> list[Frame]:
    frames: list[Frame] = []
    sport = 30000
    for minute in range(minutes):
        n = per_minute(minute)
        for k in range(n):
            frames += tcp_handshake(host, server, T0 + minute * 60 + k * (55 / n), sport, 443, data=0)
            sport = 30000 + (sport - 29999) % 30000
    return frames


def fragmented_udp() -> list[Frame]:
    """An NFS/EDNS-style client sending 20 large UDP datagrams, fragmented normally at a 1500-byte MTU."""
    frames: list[Frame] = []
    for i in range(20):
        big = WORKSTATION.udp(SERVER, 800 + i, 2049, b"\x00" * 4000)
        frames += [(T0 + i + k * 0.0001, f) for k, f in enumerate(fragment(big, 1480))]
    return frames


def growing_workload() -> list[Frame]:
    """A host whose new-connection rate grows 10% per minute for 20 minutes (a service ramping up)."""
    return _steady_connections(WORKSTATION, SERVER, 20, lambda m: round(20 * 1.1**m))


# --- attacks ----------------------------------------------------------------


def syn_scan_1000() -> list[Frame]:
    """nmap -sS default: 1000 ports, ~1ms apart; 22, 80, 443 open."""
    frames: list[Frame] = []
    for i, port in enumerate(_ports(1000)):
        frames += syn_probe(ATTACKER, SERVER, T0 + i * 0.001, port, open_=port in (22, 80, 443))
    return frames


def xmas_scan() -> list[Frame]:
    """nmap -sX: 200 ports with FIN|PSH|URG. Open ports stay silent, closed ones RST."""
    frames: list[Frame] = []
    for i, port in enumerate(_ports(200)):
        frames += syn_probe(ATTACKER, SERVER, T0 + i * 0.002, port, open_=port in (22, 80), flags=FIN | PSH | URG)
    return frames


def slow_scan() -> list[Frame]:
    """nmap -T1 style: one probe every 15s. Designed to stay under rate thresholds."""
    frames: list[Frame] = []
    for i, port in enumerate(_ports(100)):
        frames += syn_probe(ATTACKER, SERVER, T0 + i * 15, port, open_=port == 22)
    return frames


def ping_sweep() -> list[Frame]:
    """nmap -sn -PE 10.0.0.0/24 from outside the L2 segment: ICMP echo to 254 hosts."""
    alive = {h.ip: h for h in LAN_ALIVE}
    frames: list[Frame] = []
    for i in range(1, 255):
        ip = f"10.0.0.{i}"
        ts = T0 + i * 0.004
        frames.append((ts, ATTACKER.icmp_echo(ip, GATEWAY.mac)))
        if ip in alive:
            frames.append((ts + 0.001, alive[ip].icmp_echo(ATTACKER.ip, ATTACKER.mac, reply=True)))
    return frames


def arp_sweep() -> list[Frame]:
    """nmap -sn / arp-scan on the local segment: ARP who-has for 254 addresses."""
    alive = {h.ip: h for h in LAN_ALIVE}
    frames: list[Frame] = []
    for i in range(1, 255):
        ip = f"10.0.0.{i}"
        ts = T0 + i * 0.002
        frames.append((ts, ATTACKER.arp_request(ip)))
        if ip in alive:
            frames.append((ts + 0.0005, alive[ip].arp_reply(ATTACKER)))
    return frames


def arp_spoof_mitm() -> list[Frame]:
    """arpspoof/ettercap MITM: attacker poisons workstation and gateway every 2s."""
    frames: list[Frame] = [
        (T0, WORKSTATION.arp_request(GATEWAY.ip)),
        (T0 + 0.001, GATEWAY.arp_reply(WORKSTATION)),
        (T0 + 0.002, GATEWAY.arp_request(WORKSTATION.ip)),
        (T0 + 0.003, WORKSTATION.arp_reply(GATEWAY)),
    ]
    for i in range(30):
        ts = T0 + 10 + i * 2
        frames.append((ts, ATTACKER.arp_reply(WORKSTATION, claimed_ip=GATEWAY.ip)))
        frames.append((ts + 0.01, ATTACKER.arp_reply(GATEWAY, claimed_ip=WORKSTATION.ip)))
        if i % 10 == 5:  # the real gateway answers a genuine request now and then
            frames.append((ts + 1.0, WORKSTATION.arp_request(GATEWAY.ip)))
            frames.append((ts + 1.001, GATEWAY.arp_reply(WORKSTATION)))
    return frames


def udp_scan() -> list[Frame]:
    """nmap -sU: 200 UDP ports; DNS (53) and SNMP (161) answer, ICMP port unreachable is rate-limited to 1/s."""
    frames: list[Frame] = []
    last_icmp = -1.0
    for i, port in enumerate(_ports(200)):
        ts = T0 + i * 0.01
        probe = ATTACKER.udp(SERVER, 50000 + i, port, b"")
        frames.append((ts, probe))
        if port in (53, 161):
            frames.append((ts + 0.001, SERVER.udp(ATTACKER, port, 50000 + i, b"reply")))
        elif ts - last_icmp >= 1.0:  # Linux icmp_ratelimit: ~1 error per second
            frames.append((ts + 0.001, SERVER.icmp_unreachable(ATTACKER, probe)))
            last_icmp = ts
    return frames


def fragmented_scan() -> list[Frame]:
    """nmap -f -sS: 50 SYN probes, each split into 8-byte fragments so no single packet holds the TCP header."""
    frames: list[Frame] = []
    for i, port in enumerate(_ports(50)):
        probe = ATTACKER.tcp(SERVER, 40000 + i, port, SYN)
        frames += [(T0 + i * 0.01 + k * 0.0001, f) for k, f in enumerate(fragment(probe, 8))]
    return frames


def syn_flood_spoofed() -> list[Frame]:
    """hping3 -S --flood --rand-source: 6000 SYNs to port 80 in 6s; the server SYN-ACKs into the void."""
    rng = random.Random(4242)
    frames: list[Frame] = []
    for i in range(6000):
        src = Host(f"198.18.{rng.randrange(256)}.{rng.randrange(1, 255)}", GATEWAY.mac)
        ts = T0 + i * 0.001
        sport = rng.randrange(1024, 65535)
        frames.append((ts, src.tcp(SERVER, sport, 80, SYN, seq=rng.randrange(1 << 32))))
        frames.append((ts + 0.0002, SERVER.tcp(src, 80, sport, SYN | ACK, seq=777, ack=1)))
    return frames


def dns_tunnel() -> list[Frame]:
    """dnscat2-style tunnel: 300 TXT queries carrying hex-encoded chunks under t.tunnel-example.net."""
    rng = random.Random(99)
    frames: list[Frame] = []
    for i in range(300):
        chunk = "".join(rng.choice("0123456789abcdef") for _ in range(48))
        name = f"{chunk[:30]}.{chunk[30:]}.t.tunnel-example.net"
        frames.append((T0 + i * 0.4, WORKSTATION.dns_query(RESOLVER, name, sport=42000 + i % 1000, qid=i, qtype=16)))
    return frames


def dga_nxdomain() -> list[Frame]:
    """DGA malware trying 60 generated domains in 30s; all but one answer NXDOMAIN."""
    rng = random.Random(7)
    frames: list[Frame] = []
    tlds = ["com", "net", "org", "info", "biz"]
    for i in range(60):
        label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(12, 18)))
        name = f"{label}.{tlds[i % len(tlds)]}"
        rcode = 0 if i == 59 else RCODE_NXDOMAIN
        frames.append((T0 + i * 0.5, WORKSTATION.dns_query(RESOLVER, name, sport=43000 + i, qid=500 + i)))
        frames.append((T0 + i * 0.5 + 0.02, dns_response(RESOLVER, WORKSTATION, name, 500 + i, rcode, 43000 + i)))
    return frames


def connection_burst() -> list[Frame]:
    """A workstation with ~10 connections/min for 15 minutes suddenly opens 600 in one minute (brute force)."""
    return _steady_connections(WORKSTATION, SERVER, 16, lambda m: 600 if m == 15 else 8 + m % 5)


def exfil_volume() -> list[Frame]:
    """A workstation uploads ~150 KB/min for 15 minutes, then 30 MB to an external host in one minute."""
    frames: list[Frame] = []
    for minute in range(15):
        frames += bulk_transfer(WORKSTATION, SERVER, T0 + minute * 60, 30000 + minute, 443, 150_000, 20)
    outside = Host("203.0.113.50", GATEWAY.mac)
    frames += bulk_transfer(WORKSTATION, outside, T0 + 15 * 60 + 1, 31000, 443, 30_000_000, 50)
    return frames


def _monitor_allowlisted() -> Config:
    return Config(allowlist=[MONITOR.ip])


SCENARIOS: list[Scenario] = [
    Scenario("benign_office", "benign", benign_office.__doc__ or "", benign_office),
    Scenario(
        "monitoring_poller",
        "benign",
        monitoring_poller.__doc__ or "",
        monitoring_poller,
        note="Expected false positive with default config: indistinguishable from a ping sweep by rate alone.",
    ),
    Scenario(
        "monitoring_poller_allowlisted",
        "benign",
        "Same traffic, with the monitoring server in the allowlist.",
        monitoring_poller,
        config=_monitor_allowlisted,
    ),
    Scenario(
        "dhcp_reassignment",
        "benign",
        dhcp_reassignment.__doc__ or "",
        dhcp_reassignment,
        note="Expected false positive (MEDIUM): a single binding change cannot be told apart from spoofing.",
    ),
    Scenario(
        "passive_ftp",
        "benign",
        passive_ftp.__doc__ or "",
        passive_ftp,
        note="Every connection succeeds: the window rule suppresses it (max_open_ratio), TRW sees only successes.",
    ),
    Scenario("flash_crowd", "benign", flash_crowd.__doc__ or "", flash_crowd, note="SYN-flood look-alike"),
    Scenario("voip_call", "benign", voip_call.__doc__ or "", voip_call, note="UDP-scan look-alike"),
    Scenario("cdn_lookups", "benign", cdn_lookups.__doc__ or "", cdn_lookups, note="DNS-tunnel look-alike"),
    Scenario(
        "search_suffix_nxdomain",
        "benign",
        search_suffix_nxdomain.__doc__ or "",
        search_suffix_nxdomain,
        note="Expected false positive: indistinguishable from DGA by count; evidence shows one domain, readable names.",
    ),
    Scenario("fragmented_udp", "benign", fragmented_udp.__doc__ or "", fragmented_udp, note="Fragmentation look-alike"),
    Scenario(
        "growing_workload",
        "benign",
        growing_workload.__doc__ or "",
        growing_workload,
        note="Connection-rate look-alike: the baseline adapts to gradual growth.",
    ),
    Scenario(
        "syn_scan_1000",
        "attack",
        syn_scan_1000.__doc__ or "",
        syn_scan_1000,
        {("portscan", "10.0.0.66->10.0.0.10"), ("trw", "10.0.0.66")},
    ),
    Scenario("xmas_scan", "attack", xmas_scan.__doc__ or "", xmas_scan, {("portscan", "10.0.0.66->10.0.0.10")}),
    Scenario(
        "slow_scan",
        "attack",
        slow_scan.__doc__ or "",
        slow_scan,
        {("portscan", "10.0.0.66->10.0.0.10"), ("trw", "10.0.0.66")},
        note="Window rule misses it (at most 5 probes per 60s, threshold 15); TRW has no window and detects it.",
    ),
    Scenario("ping_sweep", "attack", ping_sweep.__doc__ or "", ping_sweep, {("hostsweep", "10.0.0.66")}),
    Scenario("arp_sweep", "attack", arp_sweep.__doc__ or "", arp_sweep, {("hostsweep", "10.0.0.66")}),
    Scenario(
        "arp_spoof_mitm",
        "attack",
        arp_spoof_mitm.__doc__ or "",
        arp_spoof_mitm,
        {("arpspoof", GATEWAY.ip), ("arpspoof", WORKSTATION.ip)},
    ),
    Scenario(
        "fragmented_scan",
        "attack",
        fragmented_scan.__doc__ or "",
        fragmented_scan,
        {("fragments", "10.0.0.66")},
        note="Probes themselves are invisible to the scan rules (no reassembly); the fragmentation is detected.",
    ),
    Scenario("udp_scan", "attack", udp_scan.__doc__ or "", udp_scan, {("udpscan", "10.0.0.66->10.0.0.10")}),
    Scenario(
        "syn_flood_spoofed", "attack", syn_flood_spoofed.__doc__ or "", syn_flood_spoofed, {("synflood", SERVER.ip)}
    ),
    Scenario("dns_tunnel", "attack", dns_tunnel.__doc__ or "", dns_tunnel, {("dnstunnel", WORKSTATION.ip)}),
    Scenario("dga_nxdomain", "attack", dga_nxdomain.__doc__ or "", dga_nxdomain, {("nxdomain", WORKSTATION.ip)}),
    Scenario(
        "connection_burst",
        "attack",
        connection_burst.__doc__ or "",
        connection_burst,
        {("connrate", WORKSTATION.ip)},
    ),
    Scenario("exfil_volume", "attack", exfil_volume.__doc__ or "", exfil_volume, {("volume", WORKSTATION.ip)}),
]


def get(name: str) -> Scenario:
    for sc in SCENARIOS:
        if sc.name == name:
            return sc
    raise KeyError(name)
