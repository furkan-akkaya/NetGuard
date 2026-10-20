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
    "passive_ftp": (0, 1, 0),
    "syn_scan_1000": (1, 0, 0),
    "xmas_scan": (1, 0, 0),
    "slow_scan": (0, 0, 1),
    "ping_sweep": (1, 0, 0),
    "arp_sweep": (1, 0, 0),
    "arp_spoof_mitm": (2, 0, 0),
}


def test_every_scenario_has_an_expectation():
    assert {s.name for s in SCENARIOS} == set(EXPECTED)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_scenario_outcome(scenario, tmp_path):
    r = run_scenario(scenario, tmp_path)
    assert (len(r.tp), len(r.fp), len(r.fn)) == EXPECTED[scenario.name]
