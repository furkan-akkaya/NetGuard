"""Built-in detectors. Add new ones to :data:`DETECTORS`."""

from __future__ import annotations

from netguard.config import Config
from netguard.detectors.arpspoof import ArpSpoofDetector
from netguard.detectors.base import Detector
from netguard.detectors.connrate import ConnRateDetector
from netguard.detectors.dnstunnel import DnsTunnelDetector
from netguard.detectors.fragments import FragmentDetector
from netguard.detectors.hostsweep import HostSweepDetector
from netguard.detectors.nxdomain import NxdomainDetector
from netguard.detectors.portscan import PortScanDetector
from netguard.detectors.synflood import SynFloodDetector
from netguard.detectors.trw import TrwDetector
from netguard.detectors.udpscan import UdpScanDetector
from netguard.detectors.volume import VolumeDetector

#: Every built-in detector, in the order they see each packet.
DETECTORS: tuple[type[Detector], ...] = (
    PortScanDetector,
    TrwDetector,
    UdpScanDetector,
    HostSweepDetector,
    SynFloodDetector,
    ArpSpoofDetector,
    DnsTunnelDetector,
    NxdomainDetector,
    FragmentDetector,
    ConnRateDetector,
    VolumeDetector,
)

__all__ = ["DETECTORS", "Detector", "build_detectors"]


def build_detectors(config: Config) -> list[Detector]:
    """Instantiate every detector whose config section has ``enabled = true``."""
    return [cls(config) for cls in DETECTORS if getattr(config, cls.name).enabled]
