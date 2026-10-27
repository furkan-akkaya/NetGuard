"""Release gates used by .github/workflows/release.yml (standard library only).

    python scripts/release_checks.py versions v1.0.0rc1
    python scripts/release_checks.py sdist dist/netguard-1.0.0rc1.tar.gz
    /tmp/clean/bin/python scripts/release_checks.py installed dist/netguard-1.0.0rc1-requirements.txt

* ``versions``: pyproject.toml, src/netguard/__init__.py and
  frontend/package.json carry the tag's version.
* ``sdist``: the source archive holds only files tracked by git (plus the
  generated dashboard bundle and build metadata) and everything needed to run
  the tests and rebuild the dashboard. Nothing local (captures, untracked
  notes) can slip in.
* ``installed``: run with the clean environment's interpreter. Every installed
  distribution has the version pinned in the lock export, and every pinned
  requirement without an environment marker is installed. The SBOM is made
  from the same lock, so it describes what was tested.
"""

from __future__ import annotations

import importlib.metadata
import json
import re
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GENERATED = ("src/netguard/web/static/",)  # built by pnpm before `uv build`
BUILD_FILES = {"PKG-INFO", "pyproject.toml.orig"}
REQUIRED = ("uv.lock", "tests/", "frontend/package.json", "frontend/pnpm-lock.yaml", "frontend/src/", "docs/")
IGNORED_DISTS = {"netguard", "pip", "setuptools", "wheel"}


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def check_versions(tag: str) -> list[str]:
    want = tag.removeprefix("v")
    found = {
        "pyproject.toml": tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"],
        "frontend/package.json": json.loads((ROOT / "frontend/package.json").read_text())["version"],
    }
    match = re.search(r'^__version__ = "([^"]+)"', (ROOT / "src/netguard/__init__.py").read_text(), re.M)
    found["src/netguard/__init__.py"] = match.group(1) if match else "?"
    return [f"{path}: version {v}, tag {tag}" for path, v in found.items() if v != want]


def check_sdist(archive: Path) -> list[str]:
    tracked = set(subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split())
    with tarfile.open(archive) as tar:
        names = [m.name.split("/", 1)[1] for m in tar.getmembers() if m.isfile() and "/" in m.name]
    errors = [
        f"not tracked by git: {name}"
        for name in names
        if name not in tracked and name not in BUILD_FILES and not name.startswith(GENERATED)
    ]
    errors += [f"missing from the source archive: {req}" for req in REQUIRED if not any(n.startswith(req) for n in names)]
    return errors


def check_installed(requirements: Path) -> list[str]:
    pinned: dict[str, tuple[str, bool]] = {}  # name -> (version, has marker)
    for line in requirements.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        spec, _, marker = line.partition(";")
        name, sep, version = spec.strip().partition("==")
        if not sep:
            return [f"lock export line is not pinned: {line}"]
        pinned[_norm(name)] = (version.strip(), bool(marker.strip()))
    installed = {_norm(d.metadata["Name"]): d.version for d in importlib.metadata.distributions()}
    errors = []
    for name, version in sorted(installed.items()):
        if name in IGNORED_DISTS:
            continue
        if name not in pinned:
            errors.append(f"installed but not in the lock: {name}=={version}")
        elif pinned[name][0] != version:
            errors.append(f"{name}: installed {version}, locked {pinned[name][0]}")
    errors += [
        f"locked but not installed: {name}=={version}"
        for name, (version, marker) in sorted(pinned.items())
        if not marker and name not in installed
    ]
    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] not in {"versions", "sdist", "installed"}:
        print(__doc__, file=sys.stderr)
        return 2
    command, arg = argv
    if command == "versions":
        errors = check_versions(arg)
    elif command == "sdist":
        errors = check_sdist(Path(arg))
    else:
        errors = check_installed(Path(arg))
    for error in errors:
        print(f"release check failed: {error}", file=sys.stderr)
    if not errors:
        print(f"release check passed: {command}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
