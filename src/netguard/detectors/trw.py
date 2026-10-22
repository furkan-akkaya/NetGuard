"""Scan detection by connection outcome: Threshold Random Walk (TRW).

Jung, Paxson, Berger, Balakrishnan, "Fast Portscan Detection Using Sequential
Hypothesis Testing", IEEE S&P 2004.

Idea: a benign host mostly connects to services that exist, a scanner mostly
probes ones that do not. Each *first-contact* connection attempt of a source
(a ``(destination, port)`` it has not tried before) is a Bernoulli trial whose
success probability is θ₀ for a benign host and θ₁ for a scanner (θ₁ < θ₀).
After each outcome the log-likelihood ratio moves:

* success (SYN-ACK): ``Λ += ln(θ₁/θ₀)``           (towards benign)
* failure (RST, or no answer before the handshake timeout):
  ``Λ += ln((1-θ₁)/(1-θ₀))``                       (towards scanner)

Wald's sequential probability ratio test stops as soon as ``Λ`` crosses one of
two thresholds derived from the wanted detection and false-positive
probabilities: ``ln(P_D/P_F)`` → scanner, ``ln((1-P_D)/(1-P_F))`` → benign.
With the defaults (θ₀=0.8, θ₁=0.2, P_D=0.99, P_F=0.01) each failure adds
ln 4 ≈ 1.39, so 4 consecutive failures decide "scanner"; 4 successes reset
the walk to benign.

Unlike the window detector (NG-SCAN-001) this has no time window, so slow
scans are caught as long as the source state survives (``state_timeout``),
and successful connections *lower* suspicion, so bursts of working
connections (passive FTP) are not scans. Deviations from the paper, both
documented in the rule page:

* a contact is a ``(destination, port)`` pair, not a destination host, so
  vertical scans of one host are covered too;
* ``min_failures`` additionally requires a minimum number of failed first
  contacts, because a client that tries four dead services in a row is common
  in real networks.

Outcomes of attempts still pending when the input ends are unknown and are
not counted (a capture that stops mid-handshake is not a failure).
"""

from __future__ import annotations

import math
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field

from netguard.config import Config
from netguard.detectors.base import Detector, RuleInfo, as_early
from netguard.flows import ANSWERED, ATTEMPT, REJECTED, Flow
from netguard.models import Alert, Severity, Technique

T1046 = Technique("T1046", "Network Service Discovery")
RULE_ID = "NG-SCAN-002"

Contact = tuple[str, int]  # (destination ip, port)
_UNANSWERED_STATES = frozenset({"S0", "RSTOS0", "SH"})
_RESOLVED = -1


@dataclass(slots=True)
class _Source:
    first_seen: float
    last_seen: float
    llr: float = 0.0  # log-likelihood ratio of "scanner" vs "benign"
    # Every first contact -> source port of the attempt still awaiting its
    # outcome, or _RESOLVED. One dict serves as both the "seen before" set
    # and the pending-outcome index (memory matters under spoofed floods).
    contacts: dict[Contact, int] = field(default_factory=dict)
    successes: int = 0
    rejected: int = 0
    unanswered: int = 0
    resets_to_benign: int = 0
    scanner_since: float | None = None
    decided_after: int = 0
    failed_sample: list[Contact] | None = None  # created on the first failure

    @property
    def failures(self) -> int:
        return self.rejected + self.unanswered

    @property
    def outcomes(self) -> int:
        return self.successes + self.failures


class TrwDetector(Detector):
    name = "trw"
    rules = (RuleInfo(RULE_ID, "Scan detected by connection outcomes (TRW)", T1046),)

    def __init__(self, config: Config) -> None:
        self.cfg = config.trw
        self.global_cfg = config
        t0, t1 = self.cfg.benign_success_probability, self.cfg.scanner_success_probability
        pd, pf = self.cfg.detection_probability, self.cfg.false_positive_probability
        self.step_success = math.log(t1 / t0)
        self.step_failure = math.log((1 - t1) / (1 - t0))
        self.upper = math.log(pd / pf)
        self.lower = math.log((1 - pd) / (1 - pf))
        # Undecided sources, least recently updated first, and decided scanners
        # awaiting their report. Keeping them apart lets tick() expire the
        # undecided ones by popping from the front only.
        self._sources: OrderedDict[str, _Source] = OrderedDict()
        self._scanners: dict[str, _Source] = {}
        self.evicted_sources = 0
        self.early_warning = config.alerts.early_warning
        self.max_age = config.alerts.max_incident_age_seconds
        self._decided: list[str] = []  # newly decided scanners awaiting an early warning

    def on_conn_event(self, event: str, flow: Flow, ts: float) -> Iterable[Alert]:
        if flow.proto != "tcp":
            return ()
        src = flow.src_ip
        if event == ATTEMPT:
            if self.global_cfg.is_allowlisted(src):
                return ()
            state = self._source(src, ts)
            contact = (flow.dst_ip, flow.dst_port)
            if contact in state.contacts or len(state.contacts) >= self.cfg.max_contacts_per_source:
                return ()  # not a first contact (or the per-source budget is spent)
            state.contacts[contact] = flow.src_port
        elif event in (ANSWERED, REJECTED):
            self._outcome(flow, ts, success=event == ANSWERED)
        return ()

    def on_flow_end(self, flow: Flow) -> Iterable[Alert]:
        # No answer before the handshake timed out: a failed first contact.
        # "eof" and "evicted" endings are not timeouts: the outcome is unknown.
        if flow.proto == "tcp" and flow.end_reason == "idle" and flow.state in _UNANSWERED_STATES:
            self._outcome(flow, flow.last_seen, success=False, unanswered=True)
        return ()

    def _source(self, src: str, ts: float) -> _Source:
        state = self._scanners.get(src)
        if state is not None:
            state.last_seen = ts
            return state
        state = self._sources.get(src)
        if state is None:
            if len(self._sources) >= self.cfg.max_sources:
                self._sources.popitem(last=False)
                self.evicted_sources += 1
            state = self._sources[src] = _Source(first_seen=ts, last_seen=ts)
        else:
            self._sources.move_to_end(src)
        state.last_seen = ts
        return state

    def _outcome(self, flow: Flow, ts: float, success: bool, unanswered: bool = False) -> None:
        src = flow.src_ip
        state = self._scanners.get(src) or self._sources.get(src)
        if state is None:
            return
        contact = (flow.dst_ip, flow.dst_port)
        if state.contacts.get(contact, _RESOLVED) != flow.src_port:
            return  # not the first-contact attempt we are waiting for
        state.contacts[contact] = _RESOLVED
        if state.scanner_since is None:
            self._sources.move_to_end(src)
        state.last_seen = max(state.last_seen, ts)
        if success:
            state.successes += 1
            state.llr += self.step_success
        else:
            if unanswered:
                state.unanswered += 1
            else:
                state.rejected += 1
            state.llr += self.step_failure
            if state.failed_sample is None:
                state.failed_sample = []
            if len(state.failed_sample) < 25:
                state.failed_sample.append(contact)
        if state.scanner_since is not None:
            return  # already decided: keep collecting evidence for the report
        if state.llr >= self.upper and state.failures >= self.cfg.min_failures:
            state.scanner_since = ts
            state.decided_after = state.outcomes
            self._scanners[src] = self._sources.pop(src)
            if self.early_warning:
                self._decided.append(src)
        elif state.llr <= self.lower:
            # Benign so far: restart the walk (Jung et al.), keep the contact history.
            state.llr = 0.0
            state.resets_to_benign += 1

    def tick(self, now: float) -> Iterable[Alert]:
        while self._sources:
            src, state = next(iter(self._sources.items()))
            if now - state.last_seen <= self.cfg.state_timeout_seconds:
                break
            del self._sources[src]
        decided, self._decided = self._decided, []
        early = as_early(self._alert(s, self._scanners[s]) for s in decided if s in self._scanners)
        done = [
            s
            for s, st in self._scanners.items()
            if now - st.last_seen > self.cfg.idle_timeout_seconds or now - st.first_seen > self.max_age
        ]
        return early + [self._alert(s, self._scanners.pop(s)) for s in done]

    def flush(self) -> Iterable[Alert]:
        alerts = [self._alert(src, st) for src, st in self._scanners.items()]
        self._scanners.clear()
        self._sources.clear()
        return alerts

    def _alert(self, src: str, st: _Source) -> Alert:
        hosts = {dst for dst, _ in st.contacts}
        ports = {port for _, port in st.contacts}
        severity = Severity.HIGH if st.failures >= self.cfg.high_severity_failures else Severity.MEDIUM
        if len(hosts) == 1:
            shape = f"{len(ports)} ports on {next(iter(hosts))}"
        elif len(ports) == 1:
            shape = f"port {next(iter(ports))} on {len(hosts)} hosts"
        else:
            shape = f"{len(ports)} ports on {len(hosts)} hosts"
        summary = (
            f"{src} made {st.outcomes} first-contact TCP connection attempts ({shape}) with known outcome: "
            f"{st.failures} failed ({st.rejected} rejected, {st.unanswered} unanswered), {st.successes} succeeded. "
            f"Sequential hypothesis test (TRW): the likelihood ratio crossed the scanner threshold "
            f"(P_D={self.cfg.detection_probability:g}, P_F={self.cfg.false_positive_probability:g}) "
            f"after {st.decided_after} outcomes."
        )
        if st.resets_to_benign:
            summary += f" Earlier activity was judged benign {st.resets_to_benign} time(s) before."
        return Alert(
            detector=self.name,
            rule_id=RULE_ID,
            title=self.rules[0].title,
            severity=severity,
            first_seen=st.first_seen,
            last_seen=st.last_seen,
            src=src,
            dst=next(iter(hosts)) if len(hosts) == 1 else None,
            technique=T1046,
            summary=summary,
            evidence={
                "first_contacts": len(st.contacts),
                "outcomes": st.outcomes,
                "successes": st.successes,
                "failures": st.failures,
                "rejected": st.rejected,
                "unanswered": st.unanswered,
                "success_ratio": round(st.successes / st.outcomes, 4) if st.outcomes else None,
                "distinct_hosts": len(hosts),
                "distinct_ports": len(ports),
                "decided_after_outcomes": st.decided_after,
                "decided_at_seconds": round(st.scanner_since - st.first_seen, 3) if st.scanner_since else None,
                "log_likelihood_ratio": round(st.llr, 2),
                "sample_failed_targets": [f"{d}:{p}" for d, p in st.failed_sample or ()],
                "threshold": {
                    "theta_benign": self.cfg.benign_success_probability,
                    "theta_scanner": self.cfg.scanner_success_probability,
                    "detection_probability": self.cfg.detection_probability,
                    "false_positive_probability": self.cfg.false_positive_probability,
                    "min_failures": self.cfg.min_failures,
                },
            },
        )
