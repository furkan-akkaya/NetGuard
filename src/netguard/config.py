"""Detector configuration, loaded from TOML (stdlib ``tomllib``, no extra deps).

Every threshold that influences an alert lives here, so tuning is explicit and
reviewable. Unknown keys are rejected: a typo such as ``min_distinct_port``
should fail loudly instead of silently running with the default.
"""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    pass


@dataclass
class PortScanConfig:
    enabled: bool = True
    window_seconds: float = 60.0
    min_distinct_ports: int = 15
    idle_timeout_seconds: float = 10.0
    high_severity_ports: int = 100
    # Do not report an incident in which more than this share of ports was open.
    max_open_ratio: float = 0.8
    max_keys: int = 100_000  # tracked (scanner, target) pairs; ~0.7 KB each


@dataclass
class HostSweepConfig:
    enabled: bool = True
    window_seconds: float = 60.0
    min_distinct_hosts: int = 15
    idle_timeout_seconds: float = 10.0
    high_severity_hosts: int = 100
    # Count TCP probes only towards private/internal addresses. A web browser
    # opens SYNs to dozens of public CDN hosts in seconds; without this filter
    # every page load would look like a sweep.
    tcp_private_only: bool = True
    max_keys: int = 100_000  # tracked sources; ~0.7 KB each


@dataclass
class UdpScanConfig:
    enabled: bool = True
    window_seconds: float = 60.0
    min_distinct_ports: int = 15
    idle_timeout_seconds: float = 10.0
    high_severity_ports: int = 100
    # Suppress the alert when this share of probed ports answered over UDP:
    # many answered ports is a busy client (VoIP, games), not a scan.
    max_answered_ratio: float = 0.5
    max_keys: int = 100_000


@dataclass
class TrwConfig:
    """Threshold Random Walk (Jung et al., 2004) on first-contact connection outcomes."""

    enabled: bool = True
    benign_success_probability: float = 0.8  # theta_0
    scanner_success_probability: float = 0.2  # theta_1
    detection_probability: float = 0.99  # P_D
    false_positive_probability: float = 0.01  # P_F
    # Practical guard on top of the test: never call a source a scanner on
    # fewer failed first contacts than this (SPRT alone decides after 4).
    min_failures: int = 5
    idle_timeout_seconds: float = 60.0  # report a scanner after this long without new outcomes
    state_timeout_seconds: float = 3600.0  # forget an undecided source idle this long
    high_severity_failures: int = 100
    max_sources: int = 50_000
    max_contacts_per_source: int = 4096

    def __post_init__(self) -> None:
        t0, t1 = self.benign_success_probability, self.scanner_success_probability
        pd, pf = self.detection_probability, self.false_positive_probability
        if not 0 < t1 < t0 < 1:
            raise ConfigError("[trw] need 0 < scanner_success_probability < benign_success_probability < 1")
        if not 0 < pf < pd < 1:
            raise ConfigError("[trw] need 0 < false_positive_probability < detection_probability < 1")


@dataclass
class SynFloodConfig:
    enabled: bool = True
    interval_seconds: float = 10.0
    min_attempts: int = 500  # new connection attempts to one ip:port per interval
    # Suspicious only if at most this share of attempts completed the handshake.
    max_completion_ratio: float = 0.2
    idle_timeout_seconds: float = 30.0
    high_severity_attempts: int = 5000
    max_targets: int = 10_000
    max_sources_per_target: int = 4096


@dataclass
class DnsTunnelConfig:
    enabled: bool = True
    window_seconds: float = 300.0
    min_distinct_subdomains: int = 50  # per (client, registered domain)
    min_mean_subdomain_length: float = 24.0
    idle_timeout_seconds: float = 60.0
    high_severity_subdomains: int = 500
    max_keys: int = 50_000


@dataclass
class NxdomainConfig:
    enabled: bool = True
    window_seconds: float = 60.0
    min_distinct_names: int = 25
    idle_timeout_seconds: float = 30.0
    high_severity_names: int = 200
    max_keys: int = 50_000


@dataclass
class FragmentConfig:
    enabled: bool = True
    # A More-Fragments fragment smaller than this is suspicious: real
    # fragmentation splits at the path MTU (>= 576 bytes in practice).
    small_fragment_bytes: int = 256
    min_fragments: int = 5  # suspicious fragments per (source, target) before reporting
    idle_timeout_seconds: float = 30.0
    high_severity_fragments: int = 100
    max_keys: int = 10_000


@dataclass
class ConnRateConfig:
    """New connection attempts per source compared with the source's own EWMA baseline."""

    enabled: bool = True
    interval_seconds: float = 60.0
    min_count: int = 100  # never alert below this many attempts per interval
    sensitivity: float = 6.0  # alert above mean + sensitivity * deviation
    warmup_intervals: int = 10
    smoothing: float = 0.1  # EWMA alpha
    max_sources: int = 10_000


@dataclass
class VolumeConfig:
    """Bytes sent per source compared with the source's own EWMA baseline."""

    enabled: bool = True
    interval_seconds: float = 60.0
    min_bytes: int = 20_000_000
    sensitivity: float = 6.0
    warmup_intervals: int = 10
    smoothing: float = 0.1
    max_sources: int = 10_000


@dataclass
class ArpSpoofConfig:
    enabled: bool = True
    # Do not re-alert on the same (ip, old_mac, new_mac) change within this period.
    realert_seconds: float = 300.0
    # IPs whose takeover is critical (e.g. the default gateway) -> HIGH severity.
    critical_ips: list[str] = field(default_factory=list)


@dataclass
class FlowConfig:
    """Flow table limits and idle timeouts (defaults follow Zeek's, see ADR-0004)."""

    max_flows: int = 200_000
    # A TCP flow with no reply yet. Long enough to absorb SYN retransmissions.
    tcp_handshake_timeout_seconds: float = 30.0
    tcp_idle_timeout_seconds: float = 300.0
    # After FIN in both directions or RST: wait for the final ACKs.
    tcp_closed_linger_seconds: float = 5.0
    udp_idle_timeout_seconds: float = 60.0
    other_idle_timeout_seconds: float = 60.0


@dataclass
class Config:
    # Sources that are authorized to scan (vulnerability scanners, monitoring).
    # Entries may be single IPs or CIDR networks.
    allowlist: list[str] = field(default_factory=list)
    portscan: PortScanConfig = field(default_factory=PortScanConfig)
    hostsweep: HostSweepConfig = field(default_factory=HostSweepConfig)
    arpspoof: ArpSpoofConfig = field(default_factory=ArpSpoofConfig)
    udpscan: UdpScanConfig = field(default_factory=UdpScanConfig)
    trw: TrwConfig = field(default_factory=TrwConfig)
    synflood: SynFloodConfig = field(default_factory=SynFloodConfig)
    dnstunnel: DnsTunnelConfig = field(default_factory=DnsTunnelConfig)
    nxdomain: NxdomainConfig = field(default_factory=NxdomainConfig)
    fragments: FragmentConfig = field(default_factory=FragmentConfig)
    connrate: ConnRateConfig = field(default_factory=ConnRateConfig)
    volume: VolumeConfig = field(default_factory=VolumeConfig)
    flows: FlowConfig = field(default_factory=FlowConfig)

    def __post_init__(self) -> None:
        try:
            self._allow_nets = [ipaddress.ip_network(a, strict=False) for a in self.allowlist]
        except ValueError as exc:
            raise ConfigError(f"allowlist: {exc}") from exc

    def is_allowlisted(self, ip: str | None) -> bool:
        if ip is None or not self._allow_nets:
            return False
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in self._allow_nets)


_SECTIONS: dict[str, type] = {
    "portscan": PortScanConfig,
    "hostsweep": HostSweepConfig,
    "arpspoof": ArpSpoofConfig,
    "udpscan": UdpScanConfig,
    "trw": TrwConfig,
    "synflood": SynFloodConfig,
    "dnstunnel": DnsTunnelConfig,
    "nxdomain": NxdomainConfig,
    "fragments": FragmentConfig,
    "connrate": ConnRateConfig,
    "volume": VolumeConfig,
    "flows": FlowConfig,
}


def _build(cls: type, data: dict[str, Any], where: str) -> Any:
    known = {f.name: f for f in fields(cls)}
    unknown = set(data) - set(known)
    if unknown:
        raise ConfigError(f"[{where}] unknown keys: {', '.join(sorted(unknown))}")
    defaults = cls()
    for name, value in data.items():
        expected = type(getattr(defaults, name))
        if expected is float and isinstance(value, int) and not isinstance(value, bool):
            value = float(value)
        if not isinstance(value, expected) or (expected is int and isinstance(value, bool)):
            raise ConfigError(f"[{where}] {name}: expected {expected.__name__}, got {type(value).__name__}")
        if isinstance(value, int | float) and not isinstance(value, bool) and value <= 0:
            raise ConfigError(f"[{where}] {name}: must be > 0")
        if (name.endswith(("_ratio", "_probability")) or name == "smoothing") and value > 1:
            raise ConfigError(f"[{where}] {name}: must be <= 1")
    return cls(**data)


def load_config(path: str | Path | None) -> Config:
    if path is None:
        return Config()
    try:
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    return config_from_mapping(raw)


def config_from_mapping(raw: Any) -> Config:
    """Validate a TOML-shaped mapping (from a file, or JSON from the API) into a :class:`Config`."""
    if not isinstance(raw, dict):
        raise ConfigError("configuration must be a mapping of sections")
    top_unknown = set(raw) - {"allowlist", *_SECTIONS}
    if top_unknown:
        raise ConfigError(f"unknown sections/keys: {', '.join(sorted(top_unknown))}")
    allowlist = raw.get("allowlist", [])
    if not isinstance(allowlist, list) or not all(isinstance(a, str) for a in allowlist):
        raise ConfigError("allowlist must be a list of strings")
    for name in _SECTIONS:
        if not isinstance(raw.get(name, {}), dict):
            raise ConfigError(f"[{name}] must be a section (a mapping)")
    sections = {name: _build(cls, raw.get(name, {}), name) for name, cls in _SECTIONS.items()}
    return Config(allowlist=allowlist, **sections)


def config_to_mapping(config: Config) -> dict[str, Any]:
    """The inverse of :func:`config_from_mapping` (a JSON-serialisable snapshot)."""
    out: dict[str, Any] = {"allowlist": list(config.allowlist)}
    for name in _SECTIONS:
        section = getattr(config, name)
        out[name] = {f.name: getattr(section, f.name) for f in fields(section)}
    return out


def merge_config(base: Config, overrides: Any) -> Config:
    """``base`` with the sections/keys in ``overrides`` replaced, validated as a whole."""
    if not isinstance(overrides, dict):
        raise ConfigError("configuration overrides must be a mapping of sections")
    merged = config_to_mapping(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return config_from_mapping(merged)
