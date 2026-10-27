"""Re-check NetGuard against the pinned results of the real lab captures.

    uv run python eval/lab/real_regression.py CAPTURE_DIR [--zeek]

CAPTURE_DIR holds the captures as NAME.pcap (for example captures/ after
eval/lab/ingest.py). For each capture listed in eval/lab/real-regression.toml
that is present, this verifies the hash prefix, analyses it with the default
configuration and compares packets, decode errors, flows, flow states and the
set of final alert rules with the pinned values. With --zeek it also runs
Zeek on the capture (a local `zeek`, else the zeek/zeek:8.2.2 image with the
network disabled) and requires `lab compare-flows` to be equal.

Exit 0 when every present capture matches, 1 on any difference, 2 when no
capture was found or the input is invalid. Captures that are missing are
listed as SKIPPED, never as passed.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

from netguard.engine import analyze_frames
from netguard.lab.compare import compare_flows
from netguard.sources import open_capture

PINNED = Path(__file__).with_name("real-regression.toml")
ZEEK_IMAGE = "zeek/zeek:8.2.2"


def _sha256(path: Path) -> str:
    with path.open("rb") as fh:
        return hashlib.file_digest(fh, "sha256").hexdigest()


def _analyse(path: Path) -> dict[str, Any]:
    with open_capture(path) as frames:
        result = analyze_frames(frames)
    stats = result.stats
    return {
        "packets": stats.packets,
        "decode_errors": stats.decode_errors,
        "flows": stats.flows_total,
        "states": dict(stats.conn_states),
        "final_rules": sorted(a.rule_id for a in result.alerts if a.stage == "final"),
    }


def _zeek(path: Path, args: list[str], workdir: Path) -> Path:
    if shutil.which("zeek"):
        cmd = ["zeek", "-r", str(path.resolve()), "LogAscii::use_json=T", *args]
    elif docker := shutil.which("docker"):
        cmd = [docker, "run", "--rm", "--network", "none", "-v", f"{path.parent.resolve()}:/in:ro"]
        cmd += ["-v", f"{workdir}:/out", "-w", "/out", ZEEK_IMAGE, "zeek", "-r", f"/in/{path.name}"]
        cmd += ["LogAscii::use_json=T", *args]
    else:
        raise RuntimeError("neither zeek nor docker is available")
    subprocess.run(cmd, cwd=workdir, check=True, capture_output=True)  # noqa: S603
    return workdir / "conn.log"


def check(capture_dir: Path, with_zeek: bool) -> int:
    pinned = tomllib.loads(PINNED.read_text(encoding="utf-8"))["capture"]
    failed = ran = 0
    for case in pinned:
        name = case["name"]
        path = capture_dir / f"{name}.pcap"
        if not path.is_file():
            print(f"SKIPPED {name}: {path} not found")
            continue
        ran += 1
        problems = []
        digest = _sha256(path)
        if not digest.startswith(case["sha256"]):
            print(f"FAIL    {name}: sha256 {digest[:16]} is not the pinned capture {case['sha256']}")
            failed += 1
            continue
        got = _analyse(path)
        for key in ("packets", "decode_errors", "flows", "states", "final_rules"):
            if got[key] != case[key]:
                problems.append(f"{key}: expected {case[key]}, got {got[key]}")
        if with_zeek:
            with tempfile.TemporaryDirectory() as tmp:
                report = compare_flows(path, _zeek(path, case["zeek_args"], Path(tmp)))
            if not report["equal"]:
                problems.append(
                    f"zeek: matched {report['matched']}, only NetGuard {report['only_netguard']}, "
                    f"only Zeek {report['only_zeek']}"
                )
        if problems:
            failed += 1
            print(f"FAIL    {name}: " + "; ".join(problems))
        else:
            zeek_note = f", Zeek equal{' with ' + ' '.join(case['zeek_args']) if case['zeek_args'] else ''}"
            print(
                f"OK      {name}: {got['packets']} packets, {got['flows']} flows, "
                f"final rules {got['final_rules'] or 'none'}{zeek_note if with_zeek else ''}"
            )
    if not ran:
        print("no pinned capture found in", capture_dir, file=sys.stderr)
        return 2
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 1 or not Path(args[0]).is_dir():
        print(__doc__, file=sys.stderr)
        return 2
    return check(Path(args[0]), "--zeek" in argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
