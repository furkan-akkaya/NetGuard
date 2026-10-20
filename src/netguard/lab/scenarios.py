"""Labelled, synthetic traffic scenarios with ground truth.

Each scenario is small, deterministic and documents *what* it simulates. Benign
scenarios are just as important as attacks: they are how we measure false
positives. Some scenarios intentionally expose known weaknesses (slow scans,
DHCP re-assignment, passive FTP) so the limitations are measured, not hidden.

Ground truth is expressed as *entities*:

* ``portscan``  -> ``"scanner->target"``
* ``hostsweep`` -> ``"scanner"``
* ``arpspoof``  -> ``"victim_ip"`` (the IP whose binding was hijacked)
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from netguard.config import Config
from netguard.lab.synth import Frame, Host, syn_probe, tcp_handshake
from netguard.models import FIN, PSH, URG

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
    """A workstation browsing the web and using internal services for 60s."""
    frames: list[Frame] = [
        (T0, WORKSTATION.arp_request(GATEWAY.ip)),
        (T0 + 0.001, GATEWAY.arp_reply(WORKSTATION)),
    ]
    t = T0 + 0.1
    for i in range(40):  # 40 different public web servers (CDNs, APIs, trackers)
        dst = f"93.184.{i // 10}.{10 + i}"
        sport = 50000 + i
        frames.append((t, WORKSTATION.dns_query(RESOLVER, f"cdn{i}.example.com", sport=sport, qid=i)))
        frames.append((t + 0.01, WORKSTATION.tcp_to_ip(GATEWAY, dst, sport, 443, 0x02)))
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
        note="Expected false positive: counting SYNs ignores that every connection succeeded (see TRW, Phase 2).",
    ),
    Scenario(
        "syn_scan_1000", "attack", syn_scan_1000.__doc__ or "", syn_scan_1000, {("portscan", "10.0.0.66->10.0.0.10")}
    ),
    Scenario("xmas_scan", "attack", xmas_scan.__doc__ or "", xmas_scan, {("portscan", "10.0.0.66->10.0.0.10")}),
    Scenario(
        "slow_scan",
        "attack",
        slow_scan.__doc__ or "",
        slow_scan,
        {("portscan", "10.0.0.66->10.0.0.10")},
        note="Expected miss: at most 5 probes fall in any 60s window (threshold 15).",
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
]


def get(name: str) -> Scenario:
    for sc in SCENARIOS:
        if sc.name == name:
            return sc
    raise KeyError(name)
