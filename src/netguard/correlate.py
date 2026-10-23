"""Alert correlation: group alerts about the same actor into incidents (ADR-0011).

Several rules can describe one activity (a SYN scan raises NG-SCAN-001 and
NG-SCAN-002), and one attacker often runs several steps (a sweep, then a port
scan, then ARP spoofing). An analyst wants one incident per actor and time
span, with the steps listed in ATT&CK tactic order.

Grouping rule: two alerts belong to the same incident when they share their
**actor** (the alert's source; for alerts without a source, such as a SYN
flood with spoofed sources, the target) and their time spans are no more than
``gap_seconds`` apart. Grouping is transitive (A~B and B~C put A, B, C
together). Early-stage alerts are folded into the final alert with the same
``alert_id``. Complexity: sorting, then one pass per actor: O(n log n).

Correlation is presentation only; it never adds or removes detections.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

#: ATT&CK technique -> tactic, for the techniques NetGuard rules map to.
TACTICS = {
    "T1046": "Discovery",
    "T1018": "Discovery",
    "T1557.002": "Credential Access",
    "T1071.004": "Command and Control",
    "T1568.002": "Command and Control",
    "T1499.001": "Impact",
    "T1599": "Defense Evasion",
}
#: Enterprise ATT&CK tactic order (a later tactic means the activity progressed).
TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]
_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
DEFAULT_GAP_SECONDS = 900.0


def _ts(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


def _latest_per_alert(alerts: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """One alert per alert_id: the final stage when present, else the latest early one."""
    chosen: dict[str, Mapping[str, Any]] = {}
    for a in alerts:
        prev = chosen.get(a["alert_id"])
        if prev is None or a.get("stage") == "final" or prev.get("stage") != "final":
            chosen[a["alert_id"]] = a
    return list(chosen.values())


def actor(alert: Mapping[str, Any]) -> str:
    return str(alert.get("src") or alert.get("dst") or "unknown")


def correlate(alerts: Iterable[Mapping[str, Any]], gap_seconds: float = DEFAULT_GAP_SECONDS) -> list[dict[str, Any]]:
    """Group alert dicts (the alert contract) into incidents, most severe first."""
    by_actor: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for a in _latest_per_alert(alerts):
        by_actor[actor(a)].append(a)

    incidents = []
    for who, items in by_actor.items():
        items.sort(key=lambda a: _ts(a["first_seen"]))
        group: list[Mapping[str, Any]] = []
        group_end = 0.0
        for a in items:
            start, end = _ts(a["first_seen"]), _ts(a["last_seen"])
            if group and start - group_end > gap_seconds:
                incidents.append(_incident(who, group))
                group = []
            group.append(a)
            group_end = max(group_end, end) if len(group) > 1 else end
        if group:
            incidents.append(_incident(who, group))
    incidents.sort(key=lambda i: (-_SEVERITY_RANK[i["severity"]], -i["confidence"], i["first_seen"]))
    return incidents


def _incident(who: str, alerts: list[Mapping[str, Any]]) -> dict[str, Any]:
    severity = max((a["severity"] for a in alerts), key=lambda s: _SEVERITY_RANK.get(s, 0))
    confidence = max(((a.get("confidence") or {}).get("score", 0) for a in alerts), default=0)
    tactics = sorted(
        {TACTICS[a["technique"]["id"]] for a in alerts if a.get("technique") and a["technique"]["id"] in TACTICS},
        key=TACTIC_ORDER.index,
    )
    rules = sorted({a["rule_id"] for a in alerts})
    targets = sorted({str(a["dst"]) for a in alerts if a.get("dst") and a.get("dst") != who})
    first = min(a["first_seen"] for a in alerts)
    last = max(a["last_seen"] for a in alerts)
    ids = sorted(a["alert_id"] for a in alerts)
    titles = ", ".join(sorted({a["title"] for a in alerts}))
    steps = f" across {len(tactics)} ATT&CK tactics ({' → '.join(tactics)})" if len(tactics) > 1 else ""
    summary = (
        f"{who}: {len(alerts)} alert{'s' if len(alerts) != 1 else ''} from {len(rules)} "
        f"rule{'s' if len(rules) != 1 else ''}{steps} — {titles}."
    )
    return {
        "incident_id": hashlib.sha256("|".join(ids).encode()).hexdigest()[:20],
        "actor": who,
        "severity": severity,
        "confidence": confidence,
        "first_seen": first,
        "last_seen": last,
        "rules": rules,
        "tactics": tactics,
        "targets": targets[:20],
        "alert_ids": ids,
        "alert_count": len(alerts),
        "summary": summary,
    }
