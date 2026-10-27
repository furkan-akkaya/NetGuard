"""Evaluate independently labelled captures without executing their provenance commands.

A manifest pins the capture bytes, the effective configuration and ground truth.
The score uses the same (detector, entity) convention as synthetic scenarios.
Delay is measured on the capture clock with early warnings enabled, not wall
clock latency or proof of a successful live capture.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import statistics
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from netguard import __version__
from netguard.config import config_to_mapping, load_config
from netguard.detectors import DETECTORS
from netguard.engine import Engine
from netguard.formats import CaptureInfo
from netguard.lab.evaluate import entity
from netguard.sources import iter_frames

MAX_MANIFEST_BYTES = 1_048_576
MAX_CAPTURES = 256
DETECTOR_NAMES = {d.name for d in DETECTORS}


class ManifestError(ValueError):
    """Invalid ground truth or capture integrity; no score should be published."""


@dataclass(frozen=True)
class CaptureCase:
    name: str
    path: Path
    sha256: str
    kind: str
    provenance: str
    tool: str
    tool_version: str
    command: str
    note: str
    config: Path | None
    expected: frozenset[tuple[str, str]]


def _text(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise ManifestError(f"{key}: expected a non-empty string (at most 4096 characters)")
    return value


def load_manifest(path: Path) -> list[CaptureCase]:
    with path.open("rb") as stream:
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ManifestError("manifest exceeds 1 MiB")
    try:
        doc = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ManifestError(f"invalid manifest: {exc}") from exc
    if set(doc) != {"schema_version", "captures"} or type(doc["schema_version"]) is not int:
        raise ManifestError("manifest requires only schema_version and captures")
    if doc["schema_version"] != 1:
        raise ManifestError("unsupported manifest schema_version (expected 1)")
    rows = doc["captures"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_CAPTURES:
        raise ManifestError(f"captures must contain 1..{MAX_CAPTURES} entries")
    cases: list[CaptureCase] = []
    names: set[str] = set()
    hashes: set[str] = set()
    allowed = {
        "name",
        "path",
        "sha256",
        "kind",
        "provenance",
        "tool",
        "tool_version",
        "command",
        "note",
        "config",
        "expected",
    }
    for row in rows:
        if not isinstance(row, dict) or set(row) - allowed:
            raise ManifestError("capture entry has unknown fields or is not a table")
        name, digest = _text(row, "name"), _text(row, "sha256").lower()
        if name in names:
            raise ManifestError(f"duplicate capture name: {name}")
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ManifestError(f"{name}: sha256 must contain 64 hexadecimal characters")
        if digest in hashes:
            raise ManifestError(f"{name}: duplicate capture bytes would overweight the score")
        kind, provenance = _text(row, "kind"), _text(row, "provenance")
        if kind not in {"attack", "benign"} or provenance not in {"lab", "synthetic", "public"}:
            raise ManifestError(f"{name}: invalid kind or provenance")
        capture_path = _text(row, "path")
        if capture_path == "-":
            raise ManifestError("manifest captures must be files, not stdin")
        expected_rows = row.get("expected")
        if not isinstance(expected_rows, list) or len(expected_rows) > 10_000:
            raise ManifestError(f"{name}: expected must be an array, including [] for benign traffic")
        expected: set[tuple[str, str]] = set()
        for label in expected_rows:
            if not isinstance(label, dict) or set(label) != {"detector", "entity"}:
                raise ManifestError(f"{name}: each expected label needs detector and entity")
            detector, target = _text(label, "detector"), _text(label, "entity")
            if detector not in DETECTOR_NAMES:
                raise ManifestError(f"{name}: unknown detector {detector}")
            pair = (detector, target)
            if pair in expected:
                raise ManifestError(f"{name}: duplicate expected label {pair}")
            expected.add(pair)
        if (kind == "attack" and not expected) or (kind == "benign" and expected):
            raise ManifestError(f"{name}: attack needs expected labels; benign needs expected = []")
        note = row.get("note", "")
        if not isinstance(note, str):
            raise ManifestError(f"{name}: note must be a string")
        config = path.parent / _text(row, "config") if "config" in row else None
        cases.append(
            CaptureCase(
                name,
                path.parent / capture_path,
                digest,
                kind,
                provenance,
                _text(row, "tool"),
                _text(row, "tool_version"),
                _text(row, "command"),
                note,
                config,
                frozenset(expected),
            )
        )
        names.add(name)
        hashes.add(digest)
    return cases


def _pairs(pairs: set[tuple[str, str]] | frozenset[tuple[str, str]]) -> list[dict[str, str]]:
    return [{"detector": detector, "entity": target} for detector, target in sorted(pairs)]


def evaluate_case(case: CaptureCase) -> dict[str, Any]:
    config = load_config(case.config)
    config.alerts.early_warning = True
    config_json = json.dumps(config_to_mapping(config), sort_keys=True, separators=(",", ":"))
    config_hash = hashlib.sha256(config_json.encode()).hexdigest()
    engine = Engine(config)
    info = CaptureInfo()
    start = time.perf_counter()
    first: float | None = None
    last: float | None = None
    frames = 0
    out_of_order = 0
    # Open once, hash and analyse that same descriptor. Reject special files;
    # they can block forever and have no stable capture identity.
    fd = os.open(case.path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ManifestError(f"{case.name}: capture must be a regular file")
        if hashlib.file_digest(stream, "sha256").hexdigest() != case.sha256:
            raise ManifestError(f"{case.name}: SHA-256 mismatch; capture was not evaluated")
        stream.seek(0)
        for ts, buf, linktype in iter_frames(stream, case.name, info):
            if not math.isfinite(ts):
                raise ManifestError(f"{case.name}: non-finite timestamp")
            # Multi-interface pcapng is often slightly out of order: report it, the
            # engine's clock only moves forward.
            if last is not None and ts < last:
                out_of_order += 1
            first = ts if first is None else min(first, ts)
            last = ts if last is None else max(last, ts)
            frames += 1
            engine.process_frame(ts, buf, linktype)
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ManifestError(f"{case.name}: capture changed during evaluation")
    if info.truncated or not frames:
        raise ManifestError(f"{case.name}: truncated or empty capture is not valid evaluation evidence")
    result = engine.finish()
    final = [a for a in result.alerts if a.stage == "final"]
    got = {entity(a) for a in final}
    tp, fp, fn = got & case.expected, got - case.expected, case.expected - got
    first_report: dict[str, float] = {}
    for alert in result.alerts:
        if alert.reported_at is not None:
            first_report[alert.alert_id] = min(first_report.get(alert.alert_id, alert.reported_at), alert.reported_at)
    delays = [
        max(0.0, first_report[a.alert_id] - a.first_seen)
        for a in final
        if entity(a) in tp and a.alert_id in first_report
    ]
    warnings = []
    if out_of_order:
        warnings.append(f"{out_of_order} frames out of order (timestamp earlier than a previous frame)")
    if result.stats.decode_errors:
        warnings.append(f"{result.stats.decode_errors} frames could not be decoded")
    if result.stats.unsupported_linktypes:
        warnings.append("unsupported link types: some frames were skipped")
    if result.stats.flows_evicted or result.stats.state_losses():
        warnings.append("bounded state was evicted; some activity may have been missed")
    duration = last - first if first is not None and last is not None else 0.0
    return {
        "name": case.name,
        "kind": case.kind,
        "provenance": case.provenance,
        "sha256": case.sha256,
        "config_sha256": config_hash,
        "tool": case.tool,
        "tool_version": case.tool_version,
        "command": case.command,
        "note": case.note,
        "frames": frames,
        "packets": result.stats.packets,
        "duration_seconds": duration,
        "analysis_seconds": time.perf_counter() - start,
        "alerts": len(final),
        "tp": _pairs(tp),
        "fp": _pairs(fp),
        "fn": _pairs(fn),
        "replay_incident_delays_seconds": delays,
        "benign_alerts_per_hour": len(final) * 3600 / duration if case.kind == "benign" and duration > 0 else None,
        "warnings": warnings,
        "capture": info.to_dict(),
        "stats": result.stats.to_dict(),
        "alert_details": [a.to_dict() for a in final],
    }


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tp, fp, fn = (sum(len(r[k]) for r in rows) for k in ("tp", "fp", "fn"))
    benign = [r for r in rows if r["kind"] == "benign"]
    seconds = sum(r["duration_seconds"] for r in benign)
    alerts = sum(r["alerts"] for r in benign)
    delays = [d for r in rows for d in r["replay_incident_delays_seconds"]]
    return {
        "captures": len(rows),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "benign_seconds": seconds,
        "benign_alerts": alerts,
        # A one-packet capture cannot supply a rate denominator. Do not silently
        # exclude its alerts while borrowing duration from another capture.
        "benign_alerts_per_hour": alerts * 3600 / seconds
        if seconds and all(r["duration_seconds"] > 0 for r in benign)
        else None,
        "replay_incident_delay_median_seconds": statistics.median(delays) if delays else None,
        "replay_incident_delay_max_seconds": max(delays) if delays else None,
        "captures_with_warnings": sum(bool(r["warnings"]) for r in rows),
    }


def run_manifest(path: Path) -> dict[str, Any]:
    rows = [evaluate_case(case) for case in load_manifest(path)]
    # Never silently mix generated and independently captured data in one score.
    groups = {p: summarize([r for r in rows if r["provenance"] == p]) for p in sorted({r["provenance"] for r in rows})}
    return {
        "schema_version": 1,
        "netguard_version": __version__,
        "captures": rows,
        "by_provenance": groups,
        "delay_scope": "capture-clock offline replay; incident onset to first report, not measured live latency",
        "label_scope": "declared ground truth, not inferred from detector output; commands are never executed",
    }


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ").replace("`", "'")


def render_manifest_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# Capture evaluation — NetGuard {__version__}",
        "",
        "| Capture | Origin | Type | Frames | Seconds | Alerts | TP | FP | FN |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    warning_lines = []
    for r in report["captures"]:
        lines.append(
            f"| {_cell(r['name'])} | {r['provenance']} | {r['kind']} | {r['frames']} | "
            f"{r['duration_seconds']:.3f} | {r['alerts']} | {len(r['tp'])} | {len(r['fp'])} | {len(r['fn'])} |"
        )
        for warning in r["warnings"]:
            warning_lines.append(f"Warning ({_cell(r['name'])}): {_cell(warning)}")
    if warning_lines:
        lines += ["", *warning_lines]
    for provenance, summary in report["by_provenance"].items():
        lines += ["", f"## {provenance} captures", ""]
        for key, value in summary.items():
            lines.append(f"- {key}: {'N/A' if value is None else value}")
    lines += [
        "",
        report["delay_scope"],
        "",
        report["label_scope"],
        "",
        "Rates use first-to-last packet time; short/quiet captures cannot establish a one-hour baseline.",
        "Full labels, hashes, configuration identity and alert evidence are available with --format json.",
    ]
    return "\n".join(lines)
