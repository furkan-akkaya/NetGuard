"""Compare directional TCP/UDP flow-state multisets with Zeek JSON conn.log.

Input is data only. Zeek is never launched and no command from a log is run.
This checks counts per directional five-tuple and state, not full semantic
compatibility, packet counters or timing. Both tools must use the same capture.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections import Counter
from pathlib import Path
from typing import Any

from netguard.config import load_config
from netguard.engine import Engine
from netguard.flows import CONN_STATES, Flow
from netguard.formats import CaptureInfo
from netguard.lab.manifest import ManifestError
from netguard.sources import iter_frames

MAX_ROWS = 500_000
MAX_LINE_BYTES = 1_048_576
StateKey = tuple[str, str, int, str, int, str]


def _zeek_key(row: dict[str, Any]) -> StateKey:
    try:
        src = str(ipaddress.ip_address(row["id.orig_h"]))
        dst = str(ipaddress.ip_address(row["id.resp_h"]))
        ports = [row["id.orig_p"], row["id.resp_p"]]
        if any(type(p) is not int or not 0 <= p <= 65535 for p in ports):
            raise ValueError("ports must be integers in 0..65535")
        if row["conn_state"] not in CONN_STATES:
            raise ValueError("unknown conn_state")
        return row["proto"], src, ports[0], dst, ports[1], row["conn_state"]
    except (KeyError, ValueError, TypeError) as exc:
        raise ManifestError(f"invalid Zeek connection row: {exc}") from exc


def read_zeek(path: Path) -> tuple[Counter[StateKey], int, str]:
    counts: Counter[StateKey] = Counter()
    ignored = 0
    rows = 0
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while raw := stream.readline(MAX_LINE_BYTES + 1):
            digest.update(raw)
            if len(raw) > MAX_LINE_BYTES:
                raise ManifestError("Zeek row exceeds 1 MiB")
            if not raw.strip():
                continue
            rows += 1
            if rows > MAX_ROWS:
                raise ManifestError(f"Zeek log exceeds {MAX_ROWS} rows; split the experiment")
            try:
                row = json.loads(raw)
            except (ValueError, UnicodeError) as exc:
                raise ManifestError("expected Zeek JSON Lines (use LogAscii::use_json=T)") from exc
            if not isinstance(row, dict) or not isinstance(row.get("proto"), str):
                raise ManifestError("Zeek row requires an object with proto")
            if row["proto"] not in {"tcp", "udp"}:
                ignored += 1
                continue
            counts[_zeek_key(row)] += 1
    if not counts:
        raise ManifestError("Zeek log has no TCP/UDP connections to compare")
    return counts, ignored, digest.hexdigest()


def compare_flows(capture: Path, zeek_log: Path, config_path: Path | None = None) -> dict[str, Any]:
    zeek, ignored, log_hash = read_zeek(zeek_log)
    actual: Counter[StateKey] = Counter()
    total = 0

    def collect(flow: Flow) -> None:
        nonlocal total
        if flow.proto not in {"tcp", "udp"}:
            return
        total += 1
        if total > MAX_ROWS:
            raise ManifestError(f"NetGuard exceeds {MAX_ROWS} flows; split the experiment")
        actual[(flow.proto, flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.state)] += 1

    engine = Engine(load_config(config_path), detectors=[], on_flow=collect)
    info = CaptureInfo()
    with capture.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        stream.seek(0)
        for ts, buf, linktype in iter_frames(stream, str(capture), info):
            engine.process_frame(ts, buf, linktype)
    result = engine.finish()
    if info.truncated:
        raise ManifestError("truncated capture is not valid comparison evidence")
    if result.stats.decode_errors or result.stats.unsupported_linktypes or result.stats.flows_evicted:
        raise ManifestError(
            "capture has decode errors, unsupported link types or flow evictions; comparison incomplete"
        )
    if not actual:
        raise ManifestError("capture has no TCP/UDP flows to compare")
    matched = sum((actual & zeek).values())
    mismatches = []
    for key in sorted(actual.keys() | zeek.keys()):
        if actual[key] != zeek[key]:
            proto, src, sport, dst, dport, state = key
            mismatches.append(
                {
                    "proto": proto,
                    "src_ip": src,
                    "src_port": sport,
                    "dst_ip": dst,
                    "dst_port": dport,
                    "state": state,
                    "netguard": actual[key],
                    "zeek": zeek[key],
                }
            )
    return {
        "schema_version": 1,
        "capture_sha256": digest,
        "zeek_log_sha256": log_hash,
        "scope": "directional TCP/UDP five-tuple + state multiset; not full Zeek compatibility",
        "netguard_flows": total,
        "zeek_flows": sum(zeek.values()),
        "zeek_non_tcp_udp_ignored": ignored,
        "matched": matched,
        "only_netguard": sum((actual - zeek).values()),
        "only_zeek": sum((zeek - actual).values()),
        "equal": actual == zeek,
        "mismatches": mismatches,
    }
