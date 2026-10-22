"""Alert export formats for SIEM ingestion.

``netguard`` is the native alert contract (``schema_version`` 1.0, see
ARCHITECTURE.md). ``ecs`` maps the same alert onto the Elastic Common Schema
(ECS 8.x field names), so Elastic, OpenSearch, Wazuh or any ECS-aware pipeline
can index NetGuard alerts without a custom parser:

=====================  ==============================================
ECS field              NetGuard source
=====================  ==============================================
``@timestamp``         ``first_seen``
``event.*``            kind ``alert``, category network/intrusion_detection,
                       ``start``/``end``, ``id`` = ``alert_id``, ``severity``,
                       ``created`` = ``reported_at``
``rule.*``             ``rule_id``, ``title``, ``detector``, rule page
``source.ip`` /        ``src`` / ``dst`` when they are IP addresses;
``destination.*``      a non-IP ``dst`` (a DNS domain) goes to
                       ``destination.domain``
``threat.*``           the ATT&CK technique
``message``            ``summary``
``netguard.*``         everything else, including the full ``evidence``
=====================  ==============================================
"""

from __future__ import annotations

import ipaddress
from typing import Any

ECS_VERSION = "8.11.0"
RULE_DOC_BASE = "https://github.com/furkan-akkaya/NetGuard/blob/main/docs/rules/"
# ECS leaves event.severity numeric and source-defined; these follow Elastic's
# detection-rule convention (low 21, medium 47, high 73).
_SEVERITY_SCORE = {"LOW": 21, "MEDIUM": 47, "HIGH": 73}
FORMATS = ("netguard", "ecs")


def _is_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def to_ecs(alert: dict[str, Any]) -> dict[str, Any]:
    """Map one alert (as returned by the store/API) to an ECS document."""
    doc: dict[str, Any] = {
        "@timestamp": alert["first_seen"],
        "ecs": {"version": ECS_VERSION},
        "message": alert["summary"],
        "event": {
            "kind": "alert",
            "category": ["network", "intrusion_detection"],
            "type": ["info"],
            "module": "netguard",
            "dataset": "netguard.alert",
            "id": alert["alert_id"],
            "start": alert["first_seen"],
            "end": alert["last_seen"],
            "severity": _SEVERITY_SCORE.get(alert["severity"], 0),
        },
        "rule": {
            "id": alert["rule_id"],
            "name": alert["title"],
            "category": alert["detector"],
            "reference": RULE_DOC_BASE + alert["rule_id"] + ".md",
            "ruleset": "netguard",
        },
        "observer": {"type": "ids", "vendor": "NetGuard", "product": "NetGuard"},
        "netguard": {
            "schema_version": alert["schema_version"],
            "stage": alert.get("stage", "final"),
            "severity": alert["severity"],
            "analysis_id": alert.get("analysis_id"),
            "evidence": alert["evidence"],
        },
    }
    if alert.get("reported_at"):
        doc["event"]["created"] = alert["reported_at"]  # when NetGuard emitted it (capture clock)
    if _is_ip(alert.get("src")):
        doc["source"] = {"ip": alert["src"]}
    dst = alert.get("dst")
    if _is_ip(dst):
        doc["destination"] = {"ip": dst}
    elif dst:
        doc["destination"] = {"domain": dst}
    technique = alert.get("technique")
    if technique:
        doc["threat"] = {
            "framework": "MITRE ATT&CK",
            "technique": {"id": [technique["id"]], "name": [technique["name"]], "reference": [technique["url"]]},
        }
    return doc


def export(alert: dict[str, Any], fmt: str) -> dict[str, Any]:
    if fmt == "ecs":
        return to_ecs(alert)
    if fmt == "netguard":
        return alert
    raise ValueError(f"unknown export format {fmt!r}")
