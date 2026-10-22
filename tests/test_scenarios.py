"""Lock in the measured behaviour on the labelled lab scenarios.

If a change improves or degrades detection, this test fails and forces an
update of docs/EVALUATION.md — results never drift silently.
"""

import pytest

from netguard.lab.evaluate import run_scenario
from netguard.lab.scenarios import SCENARIOS

# scenario -> (true positives, false positives, false negatives)
EXPECTED = {
    "benign_office": (0, 0, 0),
    "monitoring_poller": (0, 1, 0),
    "monitoring_poller_allowlisted": (0, 0, 0),
    "dhcp_reassignment": (0, 1, 0),
    "passive_ftp": (0, 0, 0),
    "flash_crowd": (0, 0, 0),
    "voip_call": (0, 0, 0),
    "cdn_lookups": (0, 0, 0),
    "search_suffix_nxdomain": (0, 1, 0),
    "growing_workload": (0, 0, 0),
    "fragmented_udp": (0, 0, 0),
    "syn_scan_1000": (2, 0, 0),
    "xmas_scan": (1, 0, 0),
    "slow_scan": (1, 0, 1),
    "ping_sweep": (1, 0, 0),
    "arp_sweep": (1, 0, 0),
    "arp_spoof_mitm": (2, 0, 0),
    "fragmented_scan": (1, 0, 0),
    "udp_scan": (1, 0, 0),
    "syn_flood_spoofed": (1, 0, 0),
    "dns_tunnel": (1, 0, 0),
    "dga_nxdomain": (1, 0, 0),
    "connection_burst": (1, 0, 0),
    "exfil_volume": (1, 0, 0),
}


def test_every_scenario_has_an_expectation():
    assert {s.name for s in SCENARIOS} == set(EXPECTED)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_scenario_outcome(scenario, tmp_path):
    r = run_scenario(scenario, tmp_path)
    assert (len(r.tp), len(r.fp), len(r.fn)) == EXPECTED[scenario.name]
