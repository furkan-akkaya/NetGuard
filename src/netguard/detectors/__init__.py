"""Built-in detectors. Add new ones to :func:`build_detectors`."""

from __future__ import annotations

from netguard.config import Config
from netguard.detectors.arpspoof import ArpSpoofDetector
from netguard.detectors.base import Detector
from netguard.detectors.hostsweep import HostSweepDetector
from netguard.detectors.portscan import PortScanDetector

__all__ = ["ArpSpoofDetector", "Detector", "HostSweepDetector", "PortScanDetector", "build_detectors"]


def build_detectors(config: Config) -> list[Detector]:
    detectors: list[Detector] = []
    if config.portscan.enabled:
        detectors.append(PortScanDetector(config))
    if config.hostsweep.enabled:
        detectors.append(HostSweepDetector(config))
    if config.arpspoof.enabled:
        detectors.append(ArpSpoofDetector(config))
    return detectors
