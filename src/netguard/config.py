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


@dataclass
class ArpSpoofConfig:
    enabled: bool = True
    # Do not re-alert on the same (ip, old_mac, new_mac) change within this period.
    realert_seconds: float = 300.0
    # IPs whose takeover is critical (e.g. the default gateway) -> HIGH severity.
    critical_ips: list[str] = field(default_factory=list)


@dataclass
class Config:
    # Sources that are authorized to scan (vulnerability scanners, monitoring).
    # Entries may be single IPs or CIDR networks.
    allowlist: list[str] = field(default_factory=list)
    portscan: PortScanConfig = field(default_factory=PortScanConfig)
    hostsweep: HostSweepConfig = field(default_factory=HostSweepConfig)
    arpspoof: ArpSpoofConfig = field(default_factory=ArpSpoofConfig)

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
    return cls(**data)


def load_config(path: str | Path | None) -> Config:
    if path is None:
        return Config()
    try:
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from exc

    top_unknown = set(raw) - {"allowlist", *_SECTIONS}
    if top_unknown:
        raise ConfigError(f"unknown sections/keys: {', '.join(sorted(top_unknown))}")
    allowlist = raw.get("allowlist", [])
    if not isinstance(allowlist, list) or not all(isinstance(a, str) for a in allowlist):
        raise ConfigError("allowlist must be a list of strings")
    sections = {name: _build(cls, raw.get(name, {}), name) for name, cls in _SECTIONS.items()}
    return Config(allowlist=allowlist, **sections)
