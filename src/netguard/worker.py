"""Analysis worker: runs one analysis job in its own process (ADR-0008).

    python -m netguard.worker DATABASE ANALYSIS_ID CAPTURE_PATH
        [--max-stored-flows N] [--memory-mb N] [--cpu-seconds N]

The runner (``jobs.py``) starts this process with resource limits and a
timeout. It reads the job's configuration snapshot from the database,
analyses the capture, streams flow records into the database in batches and
finally stores alerts and statistics in one transaction. If the job was
cancelled in the meantime, the results are discarded.

Exit codes: 0 done (or cancelled meanwhile), 2 the capture or configuration is
invalid (the message on stderr is shown to the user), anything else is a crash.
"""

from __future__ import annotations

import argparse
import contextlib
import resource
import sys
from collections.abc import Sequence

from netguard.config import ConfigError, config_from_mapping
from netguard.decode import UnsupportedLinkType
from netguard.engine import Engine
from netguard.flows import Flow
from netguard.formats import CaptureFormatError, CaptureInfo
from netguard.sources import open_capture
from netguard.store import Store

EXIT_OK, EXIT_INVALID = 0, 2
BATCH = 5000


class FlowSink:
    """Buffers finished flows and writes them in batches, up to ``limit`` rows."""

    def __init__(self, store: Store, analysis_id: str, limit: int) -> None:
        self.store = store
        self.analysis_id = analysis_id
        self.limit = limit
        self.stored = 0
        self.truncated = 0
        self._buffer: list[Flow] = []

    def __call__(self, flow: Flow) -> None:
        if self.stored + len(self._buffer) >= self.limit:
            self.truncated += 1
            return
        self._buffer.append(flow)
        if len(self._buffer) >= BATCH:
            self.flush()

    def flush(self) -> None:
        if self._buffer:
            self.store.insert_flows(self.analysis_id, self._buffer)
            self.stored += len(self._buffer)
            self._buffer = []


def run(db_path: str, analysis_id: str, capture_path: str, max_stored_flows: int) -> int:
    store = Store(db_path)
    analysis = store.get_analysis(analysis_id)
    if analysis is None or analysis["status"] != "running":
        return EXIT_OK  # cancelled (or deleted) before we started
    try:
        config = config_from_mapping(analysis["config"])
    except ConfigError as exc:
        print(f"invalid configuration: {exc}", file=sys.stderr)
        return EXIT_INVALID
    sink = FlowSink(store, analysis_id, max_stored_flows)
    engine = Engine(config, on_flow=sink)
    info = CaptureInfo()
    try:
        with open_capture(capture_path, info) as frames:
            for ts, buf, linktype in frames:
                engine.process_frame(ts, buf, linktype)
    except (CaptureFormatError, UnsupportedLinkType) as exc:
        print(f"invalid capture: {str(exc).replace(capture_path, '<capture>')}", file=sys.stderr)
        return EXIT_INVALID
    result = engine.finish()
    sink.flush()
    store.complete_analysis(
        analysis_id,
        result.alerts,
        result.stats.to_dict(),
        info.to_dict(),
        flow_count=sink.stored,
        flows_truncated=sink.truncated,
    )
    return EXIT_OK


def limit_resources(memory_mb: int, cpu_seconds: int) -> None:
    """Cap this process before touching the untrusted capture.

    ``RLIMIT_AS`` (address space) is enforced on Linux; macOS accepts or
    rejects it but does not enforce it, so on macOS only the runner's
    wall-clock timeout and ``RLIMIT_CPU`` apply.
    """
    if cpu_seconds > 0:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    if memory_mb > 0:
        limit = memory_mb * 1024 * 1024
        # Not supported on every platform (macOS); documented in ADR-0008.
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_AS, (limit, limit))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netguard.worker", description="Run one stored analysis job.")
    parser.add_argument("database")
    parser.add_argument("analysis_id")
    parser.add_argument("capture_path")
    parser.add_argument("--max-stored-flows", type=int, default=500_000)
    parser.add_argument("--memory-mb", type=int, default=0)
    parser.add_argument("--cpu-seconds", type=int, default=0)
    args = parser.parse_args(argv)
    limit_resources(args.memory_mb, args.cpu_seconds)
    try:
        return run(args.database, args.analysis_id, args.capture_path, args.max_stored_flows)
    except MemoryError:
        print("out of memory: the analysis exceeded the worker memory limit", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
