"""Explainable confidence for alerts (ADR-0011).

A detection rule says *what* was observed; confidence says how strongly that
evidence points to malicious activity rather than a benign look-alike. Each
rule starts from a base value and every factor that applies adds or subtracts
a fixed weight, with a sentence explaining why. The score is clamped to 5-95:
network evidence alone never proves intent or innocence.

Every factor is justified by how the attack or the benign look-alike behaves
on the wire (rule pages in docs/rules/ explain them). Factors are not fitted
to the lab scenarios; EVALUATION.md reports how well they separate true from
false positives there, and Phase 8 re-checks them on real captures.

The score is computed from the alert's own ``evidence``, so it is fully
reproducible from the alert JSON.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

Factors = list[tuple[str, int]]
MIN_SCORE, MAX_SCORE = 5, 95


def level(score: int) -> str:
    return "high" if score >= 70 else "medium" if score >= 40 else "low"


def _num(ev: dict[str, Any], key: str, default: float = 0.0) -> float:
    value = ev.get(key)
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else default


def _portscan(ev: dict[str, Any]) -> Factors:
    ports = max(_num(ev, "distinct_ports"), 1)
    failed = (_num(ev, "closed_ports_count") + _num(ev, "unanswered_ports_count")) / ports
    out: Factors = []
    if failed >= 0.9:
        out.append(("at least 90% of probed ports were closed or silent: the source did not know what was there", 20))
    if any(k != "SYN" for k in ev.get("probe_types", {})):
        out.append(("non-SYN probe types (NULL/FIN/XMAS) have no legitimate client use", 15))
    if ports >= 100:
        out.append(("100 or more ports on one host", 10))
    if len(ev.get("open_ports", [])) / ports > 0.5:
        out.append(("most probed ports were open, as for a client using real services", -25))
    return out


def _trw(ev: dict[str, Any]) -> Factors:
    out: Factors = []
    if _num(ev, "success_ratio", 1.0) < 0.1:
        out.append(("fewer than 10% of first contacts succeeded", 20))
    if _num(ev, "failures") >= 20:
        out.append(("20 or more failed first contacts", 10))
    if _num(ev, "distinct_hosts") >= 10 and _num(ev, "distinct_ports") >= 10:
        out.append(("many hosts and many ports: a broad scan", 5))
    return out


def _udpscan(ev: dict[str, Any]) -> Factors:
    ports = max(_num(ev, "distinct_ports"), 1)
    out: Factors = []
    unanswered = (_num(ev, "closed_ports_count") + _num(ev, "silent_ports_count")) / ports
    if unanswered >= 0.9:
        out.append(("at least 90% of probed UDP ports did not answer or were closed", 20))
    if ports >= 100:
        out.append(("100 or more UDP ports on one host", 10))
    return out


def _hostsweep(ev: dict[str, Any]) -> Factors:
    hosts = max(_num(ev, "distinct_hosts"), 1)
    alive = len(ev.get("alive_hosts", [])) / hosts
    out: Factors = []
    if alive < 0.5:
        out.append(("most probed addresses did not answer: the source was searching for hosts", 15))
    if alive >= 0.95:
        out.append(("every probed host answered: a known inventory, as polled by monitoring systems", -25))
    if hosts >= 100:
        out.append(("100 or more hosts probed", 10))
    return out


def _arpspoof(ev: dict[str, Any]) -> Factors:
    out: Factors = []
    if _num(ev, "binding_changes") >= 2:
        out.append(("the binding changed back and forth between MACs (two hosts claim the IP)", 25))
    if ev.get("unsolicited_reply"):
        out.append(("unsolicited ARP reply: nobody asked for this IP", 15))
    if ev.get("critical_ip"):
        out.append(("the IP is marked critical (e.g. the gateway)", 10))
    if _num(ev, "binding_changes") == 1 and ev.get("gratuitous") and not ev.get("unsolicited_reply"):
        out.append(("a single change announced by gratuitous ARP, as a newly connected device does", -20))
    return out


def _synflood(ev: dict[str, Any]) -> Factors:
    out: Factors = []
    if _num(ev, "completion_ratio", 1.0) <= 0.01:
        out.append(("almost no handshake completed", 20))
    sources = _num(ev, "distinct_sources")
    if sources >= 1000 and _num(ev, "single_attempt_sources") >= 0.9 * sources:
        out.append(("thousands of single-attempt sources: spoofed addresses", 10))
    if _num(ev, "answer_ratio", 1.0) < 0.1:
        out.append(("the target barely answered: an outage or filtering looks the same", -20))
    return out


def _dnstunnel(ev: dict[str, Any]) -> Factors:
    out: Factors = []
    if _num(ev, "tunnel_record_type_share") >= 0.5:
        out.append(("mostly TXT/NULL/CNAME/MX queries, which carry more data back", 20))
    if _num(ev, "mean_entropy_bits_per_char") >= 3.5:
        out.append(("high-entropy names, like encoded data", 10))
    if _num(ev, "distinct_subdomains") >= 200:
        out.append(("200 or more unique subdomains", 10))
    return out


def _nxdomain(ev: dict[str, Any]) -> Factors:
    out: Factors = []
    if _num(ev, "domain_spread") >= 0.8:
        out.append(("almost every failed name is a different domain, as a DGA produces", 25))
    if _num(ev, "mean_entropy_bits_per_char") >= 3.0:
        out.append(("random-looking labels", 10))
    if _num(ev, "registered_domains") <= 2:
        out.append(("failures concentrate on one or two domains, as with a wrong search suffix", -25))
    return out


def _fragments(ev: dict[str, Any]) -> Factors:
    kinds = ev.get("kinds", {})
    out: Factors = []
    if kinds.get("tiny_first_fragment") or kinds.get("tcp_header_split"):
        out.append(("transport headers split across fragments: no normal stack does this", 25))
    return out


def _baseline(ev: dict[str, Any]) -> Factors:
    out: Factors = []
    if _num(ev, "factor_over_baseline") >= 20:
        out.append(("20 times or more above this host's baseline", 15))
    if _num(ev, "baseline_intervals") < 30:
        out.append(("short history: the baseline may not capture this host's normal range yet", -10))
    return out


#: rule id -> (base, factor function). The base reflects how specific the
#: rule's signal is before looking at the details.
RULES: dict[str, tuple[int, Callable[[dict[str, Any]], Factors]]] = {
    "NG-SCAN-001": (60, _portscan),
    "NG-SCAN-002": (65, _trw),
    "NG-SCAN-003": (55, _udpscan),
    "NG-SWEEP-001": (55, _hostsweep),
    "NG-ARP-001": (50, _arpspoof),
    "NG-SYN-001": (60, _synflood),
    "NG-DNS-001": (55, _dnstunnel),
    "NG-DNS-002": (50, _nxdomain),
    "NG-FRAG-001": (60, _fragments),
    "NG-RATE-001": (40, _baseline),
    "NG-VOL-001": (40, _baseline),
}


def assess(rule_id: str, evidence: dict[str, Any]) -> dict[str, Any] | None:
    """Confidence for one alert, or ``None`` for a rule without a model."""
    model = RULES.get(rule_id)
    if model is None:
        return None
    base, factors_of = model
    factors = factors_of(evidence)
    score = max(MIN_SCORE, min(MAX_SCORE, base + sum(w for _, w in factors)))
    return {
        "score": score,
        "level": level(score),
        "base": base,
        "factors": [{"reason": reason, "weight": weight} for reason, weight in factors],
    }
