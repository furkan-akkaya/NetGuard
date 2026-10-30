"""Describe confidence factors on existing pinned lab captures, without tuning.

uv run python eval/lab/review_confidence.py CAPTURE_DIR [OTHER_CAPTURE_DIR ...]

Prints numeric/labelled evidence only; never raw packets, payloads or tokens.
These reused records are not independent calibration or held-out validation.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tomllib
from pathlib import Path

from netguard.engine import analyze_frames
from netguard.lab.scenarios import SCENARIOS
from netguard.sources import open_capture


def review(directories: list[Path]) -> dict[str, object]:
    pinned = tomllib.loads(Path(__file__).with_name("real-regression.toml").read_text())["capture"]
    real = []
    missing = []
    for case in pinned:
        name = case["name"]
        path = next((d / f"{name}.pcap" for d in directories if (d / f"{name}.pcap").is_file()), None)
        if path is None:
            missing.append(name)
            continue
        with path.open("rb") as fh:
            digest = hashlib.file_digest(fh, "sha256").hexdigest()
        if not digest.startswith(case["sha256"]):
            raise ValueError(f"{name}: hash differs from the pinned capture")
        with open_capture(path) as frames:
            result = analyze_frames(frames)
        real.append(
            {
                "capture": name,
                "sha256": digest,
                "kind": "benign" if name == "benign-01" else "bounded_lab_attack",
                "alerts": [
                    {"rule": a.rule_id, "confidence": a.confidence} for a in result.alerts if a.stage == "final"
                ],
            }
        )
    synthetic = []
    for scenario in SCENARIOS:
        if scenario.kind == "benign":
            result = analyze_frames(((ts, buf, 1) for ts, buf in scenario.build()), scenario.config())
            synthetic.append(
                {
                    "scenario": scenario.name,
                    "alerts": [
                        {"rule": a.rule_id, "confidence": a.confidence} for a in result.alerts if a.stage == "final"
                    ],
                }
            )
    return {
        "policy": "Descriptive reuse only; no weights fitted, no attack-probability calibration.",
        "real": real,
        "missing": missing,
        "synthetic_benign": synthetic,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: review_confidence.py CAPTURE_DIR [OTHER_CAPTURE_DIR ...]")
    print(json.dumps(review([Path(p) for p in sys.argv[1:]]), indent=2))
