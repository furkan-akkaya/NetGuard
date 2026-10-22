"""Job runner: executes queued analyses one at a time in worker processes (ADR-0008).

The runner is a daemon thread inside the API process. It never parses a
capture itself: each job runs in ``python -m netguard.worker`` with a memory
and CPU limit, and the runner enforces a wall-clock timeout and honours
cancellation by killing the worker's process group. Whatever happens, the
analysis ends in exactly one final state:

==============================  ==========================================
worker outcome                  analysis status
==============================  ==========================================
stored its results (exit 0)     ``done``
cancelled while running         ``cancelled`` (worker killed, results cleared)
invalid capture/config (exit 2) ``failed``, reason from the worker
timeout                         ``failed``, "timed out after N s"
crash / killed / out of memory  ``failed``, short reason; details in the log
==============================  ==========================================
"""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from netguard.store import Store

log = logging.getLogger("netguard.jobs")


@dataclass
class JobLimits:
    timeout_seconds: float = 600.0
    memory_mb: int = 1024
    max_stored_flows: int = 500_000
    poll_seconds: float = 0.2


class JobRunner:
    def __init__(self, store: Store, captures_dir: Path, limits: JobLimits | None = None) -> None:
        self.store = store
        self.captures_dir = captures_dir
        self.limits = limits or JobLimits()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -------------------------------------------------------------- control

    def start(self) -> None:
        requeued, failed = self.store.recover_interrupted()
        if requeued or failed:
            log.warning("recovered interrupted analyses: %d re-queued, %d failed", requeued, failed)
        self._thread = threading.Thread(target=self._loop, name="netguard-jobs", daemon=True)
        self._thread.start()

    def wake(self) -> None:
        self._wake.set()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout)

    def run_pending(self) -> int:
        """Run queued jobs synchronously until none is left (tests, CLI). Returns how many ran."""
        n = 0
        while (job := self.store.claim_next()) is not None:
            self._run(job)
            n += 1
        return n

    # ----------------------------------------------------------------- loop

    def _loop(self) -> None:
        while not self._stop.is_set():
            job = self.store.claim_next()
            if job is None:
                self._wake.wait(timeout=2.0)
                self._wake.clear()
                continue
            try:
                self._run(job)
            except Exception:
                log.exception("job runner error on analysis %s", job["id"])
                self.store.finish_analysis(job["id"], "failed", "internal error in the job runner")

    def _run(self, job: dict[str, object]) -> None:
        analysis_id = str(job["id"])
        capture = self.captures_dir / str(job["capture_id"])
        if not capture.exists():
            self.store.finish_analysis(analysis_id, "failed", "capture file is missing from storage")
            return
        cpu = int(self.limits.timeout_seconds) + 5
        cmd = [
            sys.executable,
            "-m",
            "netguard.worker",
            str(self.store.path),
            analysis_id,
            str(capture),
            "--max-stored-flows",
            str(self.limits.max_stored_flows),
            "--memory-mb",
            str(self.limits.memory_mb),
            "--cpu-seconds",
            str(cpu),
        ]
        started = time.monotonic()
        with tempfile.TemporaryFile() as err:
            proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err, start_new_session=True
            )
            outcome = self._supervise(proc, analysis_id, started)
            err.seek(0)
            stderr = err.read()[-4000:].decode("utf-8", "replace").strip()
        self._finish(analysis_id, outcome, proc.returncode, stderr, time.monotonic() - started)

    def _supervise(self, proc: subprocess.Popen[bytes], analysis_id: str, started: float) -> str:
        while True:
            remaining = self.limits.timeout_seconds - (time.monotonic() - started)
            try:
                proc.wait(timeout=max(min(self.limits.poll_seconds, remaining), 0.001))
                return "exited"
            except subprocess.TimeoutExpired:
                pass
            if self._stop.is_set():
                _kill(proc)
                return "shutdown"
            if time.monotonic() - started > self.limits.timeout_seconds:
                _kill(proc)
                return "timeout"
            if self.store.status(analysis_id) != "running":
                _kill(proc)
                return "cancelled"

    def _finish(self, analysis_id: str, outcome: str, code: int | None, stderr: str, elapsed: float) -> None:
        if outcome in ("cancelled", "shutdown"):
            # Cancelled: already final. Shutdown: stays "running" and is recovered on restart.
            return
        if outcome == "timeout":
            self.store.finish_analysis(
                analysis_id, "failed", f"timed out after {self.limits.timeout_seconds:g} s (job_timeout_seconds)"
            )
            return
        if code == 0:
            if self.store.status(analysis_id) == "running":
                self.store.finish_analysis(analysis_id, "failed", "worker exited without storing a result")
            log.info("analysis %s finished in %.1f s", analysis_id, elapsed)
            return
        if stderr:
            log.warning("analysis %s worker exit %s: %s", analysis_id, code, stderr)
        if code == 2:
            reason = stderr.splitlines()[-1][:500] if stderr else "invalid input"
        elif code == 3 or (code is not None and code < 0 and -code == signal.SIGKILL):
            reason = f"worker ran out of memory or was killed (limit {self.limits.memory_mb} MB)"
        elif code is not None and code < 0 and -code == signal.SIGXCPU:
            reason = "worker exceeded its CPU time limit"
        else:
            reason = f"worker crashed (exit code {code}); see the server log"
        self.store.finish_analysis(analysis_id, "failed", reason)


def _kill(proc: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(proc.pid, signal.SIGKILL)
    proc.wait()
