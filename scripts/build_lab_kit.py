"""Build the offline lab kit for the UTM VMs (no internet on the VMs).

    uv run python scripts/build_lab_kit.py [OUT_DIR]      # default dist/lab-kit

Produces OUT_DIR with:

* netguard-lab.pyz: NetGuard's CLI (no web extra) plus the pure-Python dpkt
  pinned in uv.lock, as one zipapp that runs with the VM's python3 (>= 3.11);
* the lab scripts from eval/lab/ and experiments.toml (ground truth);
* RUN.md (the run sheet), BUILD.json (commit, versions) and SHA256SUMS.

The kit is a lab tool, not a release. It refuses to build from a tree with
uncommitted changes to tracked files, so BUILD.json always names the exact
source; pass --allow-dirty for a local rehearsal (BUILD.json then says so).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import tomllib
import zipapp
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "eval" / "lab"
SCRIPTS = [
    "RUN.md",
    "experiments.toml",
    "victim-capture.sh",
    "victim-live-rss.sh",
    "stepped_connections.py",
    "victim_dns_queries.py",
    "victim_volume_burst.py",
    "kali-run.sh",
    "kali-benign.sh",
    "kali_arp_binding.py",
    "kali_dns_responder.py",
    "kali_rate_burst.py",
]


def _git(*args: str) -> str:
    git = shutil.which("git")
    assert git is not None, "git is required"
    return subprocess.run([git, *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()  # noqa: S603


def _locked(name: str) -> str:
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    return next(p["version"] for p in lock["package"] if p["name"] == name)


def _sha256(path: Path) -> str:
    with path.open("rb") as fh:
        return hashlib.file_digest(fh, "sha256").hexdigest()


def build(out: Path, allow_dirty: bool) -> Path:
    dirty = bool(_git("status", "--porcelain", "--untracked-files=no"))
    if dirty and not allow_dirty:
        raise SystemExit("tracked files have uncommitted changes: commit first (or --allow-dirty for a rehearsal)")
    uv = shutil.which("uv")
    if uv is None:
        raise SystemExit("uv is required")
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    dpkt = _locked("dpkt")
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    with tempfile.TemporaryDirectory() as tmp:
        wheels, tree = Path(tmp) / "wheels", Path(tmp) / "tree"
        subprocess.run([uv, "build", "--wheel", "-o", str(wheels)], cwd=ROOT, check=True, capture_output=True)  # noqa: S603
        wheel = next(wheels.glob("netguard-*.whl"))
        subprocess.run(  # noqa: S603
            [uv, "pip", "install", "--quiet", "--no-deps", "--target", str(tree), str(wheel), f"dpkt=={dpkt}"],
            cwd=ROOT,
            check=True,
        )
        shutil.rmtree(tree / "bin", ignore_errors=True)
        shutil.rmtree(tree / "netguard" / "web" / "static", ignore_errors=True)  # the CLI does not serve the UI
        (tree / "__main__.py").write_text("from netguard.cli import main\n\nraise SystemExit(main())\n")
        zipapp.create_archive(tree, out / "netguard-lab.pyz", interpreter="/usr/bin/env python3", compressed=True)
    for name in SCRIPTS:
        shutil.copy2(LAB / name, out / name)
    (out / "BUILD.json").write_text(
        json.dumps(
            {
                "project": "NetGuard lab-only offline CLI (not a release)",
                "source_commit": _git("rev-parse", "HEAD"),
                "uncommitted_changes": dirty,
                "version": version,
                "python": ">=3.11",
                "bundled_dependency": f"dpkt=={dpkt}",
                "built_utc": datetime.now(UTC).isoformat(timespec="seconds"),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    files = sorted(p for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    (out / "SHA256SUMS").write_text("".join(f"{_sha256(p)}  {p.name}\n" for p in files), encoding="utf-8")
    return out


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    out = Path(args[0]) if args else ROOT / "dist" / "lab-kit"
    kit = build(out.resolve(), "--allow-dirty" in argv)
    print(f"lab kit in {kit}:")
    print((kit / "SHA256SUMS").read_text(encoding="utf-8"), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
