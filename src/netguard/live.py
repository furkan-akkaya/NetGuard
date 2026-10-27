"""Live capture and paced replay (ADR-0010).

A *source* runs on its own thread and puts decoded-ready frames on a bounded
queue; :class:`LiveSession` runs the engine on the calling thread only, and
advances the engine's capture clock when no frame arrives for a while, so
incidents close (and alerts appear) during silence too.

Sources:

* :class:`TcpdumpSource` starts ``tcpdump`` on an explicitly named interface
  and reads pcap from its stdout. NetGuard never runs as root; tcpdump gets
  capture permission (capability, BPF group) or runs under ``sudo -n`` and
  drops privileges with ``-Z`` right after opening the device.
* :class:`ReplaySource` reads a capture file and paces it by its timestamps
  (``speed`` times real time; 0 = as fast as possible).

Back-pressure: when the queue is full the reader blocks, tcpdump's pipe and
buffer fill, and the kernel drops packets; tcpdump reports those drops, and
the session summary shows them. Memory never grows with the backlog.
"""

from __future__ import annotations

import os
import queue
import re
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO, BinaryIO

from netguard.config import Config
from netguard.engine import AnalysisResult, Engine
from netguard.flows import Flow
from netguard.formats import CaptureInfo, Frame
from netguard.models import Alert
from netguard.sources import iter_frames

#: Interface names: letters, digits and . _ - : (e.g. en0, eth0, wlp2s0, br-lan, enp0s1.100).
_IFACE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
_STATS = re.compile(r"(\d+) packets? (captured|received by filter|dropped by kernel)")
_QUEUE_FRAMES = 10_000
_END = None  # queue sentinel: the source is exhausted


class SourceError(RuntimeError):
    """The capture could not start (permissions, unknown interface, bad filter)."""


# ---------------------------------------------------------------- tcpdump


@dataclass
class CaptureSpec:
    interface: str
    bpf_filter: str = ""
    snaplen: int = 262_144
    max_packets: int | None = None
    use_sudo: bool = False


def validate_spec(spec: CaptureSpec) -> None:
    if not _IFACE.match(spec.interface) or spec.interface == "any":
        raise SourceError(
            f"invalid interface {spec.interface!r}: name one interface explicitly (see `netguard monitor --list`)"
        )
    if len(spec.bpf_filter) > 2000 or "\x00" in spec.bpf_filter:
        raise SourceError("capture filter is too long or contains NUL bytes")
    if not 64 <= spec.snaplen <= 262_144:
        raise SourceError("snaplen must be between 64 and 262144")


def tcpdump_command(spec: CaptureSpec, tcpdump: str = "tcpdump") -> list[str]:
    """The argument vector (never a shell string): -U flushes per packet, -n avoids DNS lookups."""
    validate_spec(spec)
    cmd = [tcpdump, "-i", spec.interface, "-U", "-n", "-s", str(spec.snaplen), "-w", "-"]
    if spec.max_packets:
        cmd += ["-c", str(spec.max_packets)]
    if spec.use_sudo:
        user = os.environ.get("SUDO_USER") or os.environ.get("USER") or ""
        if not user or user == "root":
            raise SourceError("--sudo needs a non-root user to drop to (tcpdump -Z)")
        cmd = ["sudo", "-n", *cmd, "-Z", user]
    if spec.bpf_filter:
        cmd.append(spec.bpf_filter)
    return cmd


def permission_help() -> str:
    import platform

    if platform.system() == "Darwin":
        return (
            "macOS: give your user access to the BPF devices (Wireshark's 'ChmodBPF' package, which adds an "
            "access_bpf group), or use --sudo with a sudoers rule for tcpdump."
        )
    return (
        "Linux: grant tcpdump the capture capability once: "
        'sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tcpdump)" (or use --sudo with a sudoers rule).'
    )


def open_new_file(path: Path) -> BinaryIO:
    """Create ``path`` mode 0600. O_EXCL: never overwrite an existing file, and
    never follow a symlink someone planted at that name (e.g. in /tmp)."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError as exc:
        raise SourceError(f"{path} already exists; choose a new file name for --write") from exc
    return os.fdopen(fd, "wb")


class _Tee:
    """Pass-through reader that also writes the raw pcap bytes to a file, up to a size limit."""

    def __init__(self, stream: IO[bytes], fh: BinaryIO | None, limit: int) -> None:
        self.stream = stream
        self.limit = limit
        self.written = 0
        self.truncated = False
        self.fh = fh

    def read(self, n: int = -1, /) -> bytes:
        data = self.stream.read(n)
        if self.fh is not None and data:
            if self.written + len(data) > self.limit:
                self.truncated = True
                self.fh.close()
                self.fh = None
            else:
                self.fh.write(data)
                self.written += len(data)
        return data

    def close(self) -> None:
        if self.fh is not None:
            self.fh.close()
            self.fh = None


class TcpdumpSource:
    """Runs tcpdump and feeds its pcap stream to the queue."""

    def __init__(
        self,
        spec: CaptureSpec,
        write_to: Path | None = None,
        write_limit: int = 1 << 30,
        command: list[str] | None = None,
    ) -> None:
        self.spec = spec
        self.name = spec.interface
        self.command = command or tcpdump_command(spec, shutil.which("tcpdump") or "tcpdump")
        self.write_to = write_to
        self.write_limit = write_limit
        self.info = CaptureInfo()
        self.proc: subprocess.Popen[bytes] | None = None
        self.stderr_lines: list[str] = []
        self._threads: list[threading.Thread] = []
        self._tee: _Tee | None = None

    def start(self, out: queue.Queue[Frame | None]) -> None:
        # Validate the output file before tcpdump starts, so a refusal leaves nothing running.
        fh = open_new_file(self.write_to) if self.write_to is not None else None
        try:
            self.proc = subprocess.Popen(  # noqa: S603 - argument vector, no shell
                self.command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
        except FileNotFoundError as exc:
            if fh is not None:
                fh.close()
            raise SourceError(f"{self.command[0]} not found: install tcpdump") from exc
        except PermissionError as exc:
            # e.g. tcpdump carries file capabilities the current process may not grant
            # (containers without CAP_NET_ADMIN in their bounding set).
            if fh is not None:
                fh.close()
            raise SourceError(f"not permitted to run {self.command[0]}: {exc.strerror}.\n{permission_help()}") from exc
        assert self.proc.stdout is not None
        assert self.proc.stderr is not None
        self._tee = _Tee(self.proc.stdout, fh, self.write_limit)
        err = threading.Thread(target=self._read_stderr, args=(self.proc.stderr,), daemon=True)
        rd = threading.Thread(target=self._read_frames, args=(out,), daemon=True)
        self._threads = [err, rd]
        err.start()
        rd.start()

    def _read_stderr(self, stream: IO[bytes]) -> None:
        for raw in stream:
            line = raw.decode("utf-8", "replace").rstrip()
            if len(self.stderr_lines) < 200:
                self.stderr_lines.append(line)

    def _read_frames(self, out: queue.Queue[Frame | None]) -> None:
        assert self._tee is not None
        try:
            for frame in iter_frames(self._tee, f"tcpdump:{self.name}", self.info):
                out.put(frame)
        except Exception as exc:  # a corrupt stream must end the session, not hang it
            self.stderr_lines.append(f"netguard: capture stream error: {exc}")
        finally:
            self._tee.close()
            out.put(_END)

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            # SIGINT makes tcpdump flush, print its statistics and exit cleanly.
            # Under sudo the signal goes to sudo, which forwards it.
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def finish(self) -> None:
        if self.proc is not None:
            self.proc.wait()
        for t in self._threads:
            t.join(timeout=5)

    def error(self) -> str | None:
        """A clear message when tcpdump failed to start capturing."""
        text = "\n".join(self.stderr_lines)
        if self.proc is None or self.proc.returncode in (0, None, -signal.SIGINT):
            return None
        if "permission" in text.lower() or "operation not permitted" in text.lower():
            return f"tcpdump has no permission to capture on {self.name}.\n{permission_help()}"
        if "a password is required" in text or "sudo:" in text:
            return "sudo -n needs a sudoers rule allowing tcpdump without a password (see docs/LIVE_CAPTURE.md)."
        detail = next((line for line in reversed(self.stderr_lines) if line.strip()), "no output")
        return f"tcpdump exited with code {self.proc.returncode}: {detail}"

    def summary(self) -> dict[str, int | str]:
        out: dict[str, int | str] = {"source": f"tcpdump on {self.name}"}
        for count, what in _STATS.findall("\n".join(self.stderr_lines)):
            out["kernel_" + what.replace(" ", "_")] = int(count)
        if self._tee is not None and self.write_to is not None:
            out["written_bytes"] = self._tee.written
            if self._tee.truncated:
                out["write_truncated"] = "pcap file reached its size limit; capture continued without writing"
        return out


def list_interfaces() -> list[str]:
    """``tcpdump -D`` (needs no capture permission on macOS and Linux)."""
    tcpdump = shutil.which("tcpdump")
    if tcpdump is None:
        raise SourceError("tcpdump not found: install tcpdump")
    result = subprocess.run([tcpdump, "-D"], capture_output=True, text=True, timeout=10, check=False)  # noqa: S603
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


# ----------------------------------------------------------------- replay


class ReplaySource:
    """Feeds a capture file at ``speed`` times its recorded pace (0 = as fast as possible)."""

    def __init__(
        self,
        path: str | Path,
        speed: float = 1.0,
        sleep: Callable[[float], object] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if speed < 0:
            raise SourceError("speed must be >= 0")
        self.path = Path(path)
        self.name = self.path.name
        self.speed = speed
        self.info = CaptureInfo()
        self.frames = 0
        self._stop = threading.Event()
        # Waiting on the stop event (not time.sleep) makes stop() take effect at once.
        self._sleep = sleep or self._stop.wait
        self._clock = clock
        self._thread: threading.Thread | None = None

    def start(self, out: queue.Queue[Frame | None]) -> None:
        if not self.path.is_file():
            raise SourceError(f"no such capture: {self.path}")
        self._thread = threading.Thread(target=self._run, args=(out,), daemon=True)
        self._thread.start()

    def _paced(self, frames: Iterator[Frame]) -> Iterator[Frame]:
        first: float | None = None
        started = self._clock()
        for frame in frames:
            if self._stop.is_set():
                return
            if self.speed > 0:
                first = frame[0] if first is None else first
                due = (frame[0] - first) / self.speed - (self._clock() - started)
                if due > 0:
                    self._sleep(due)
                    if self._stop.is_set():
                        return
            yield frame

    def _run(self, out: queue.Queue[Frame | None]) -> None:
        try:
            with open(self.path, "rb") as fh:
                for frame in self._paced(iter_frames(fh, self.name, self.info)):
                    out.put(frame)
                    self.frames += 1
        finally:
            out.put(_END)

    def stop(self) -> None:
        self._stop.set()

    def finish(self) -> None:
        if self._thread is not None:
            self._thread.join(timeout=10)

    def error(self) -> str | None:
        return None

    def summary(self) -> dict[str, int | str]:
        return {"source": f"replay of {self.name} at {self.speed:g}x" if self.speed else f"replay of {self.name}"}


# ---------------------------------------------------------------- session


@dataclass
class SessionResult:
    result: AnalysisResult
    source: dict[str, int | str]
    seconds: float
    stopped_by: str
    error: str | None = None


class LiveSession:
    """Runs one source through the engine until the source ends, ``duration`` passes, or stop() is called."""

    def __init__(
        self,
        source: TcpdumpSource | ReplaySource,
        config: Config,
        on_alert: Callable[[Alert], None] | None = None,
        on_flow: Callable[[Flow], None] | None = None,
        duration: float | None = None,
        idle_advance: float = 1.0,
        clock_rate: float = 1.0,
        on_status: Callable[[Engine], None] | None = None,
        status_every: float | None = None,
        max_alert_history: int = 10_000,
    ) -> None:
        self.source = source
        # A session can run for days: keep only the latest alert events in memory.
        # on_alert receives every one of them as it happens.
        self.engine = Engine(config, on_alert=on_alert, on_flow=on_flow, max_alert_history=max_alert_history)
        self.duration = duration
        self.idle_advance = idle_advance
        # Capture seconds per wall second (replay speed); 0 = never advance on idle.
        self.clock_rate = clock_rate
        self.on_status = on_status
        self.status_every = status_every
        self._stop = threading.Event()
        self._queue: queue.Queue[Frame | None] = queue.Queue(maxsize=_QUEUE_FRAMES)

    def stop(self) -> None:
        """Ask the session to end (thread-safe; e.g. from a signal handler)."""
        self._stop.set()

    def run(self) -> SessionResult:
        started = time.monotonic()
        anchor: tuple[float, float] | None = None  # (first capture ts, monotonic time it arrived)
        next_status = started + self.status_every if self.status_every else None
        stopped_by = "end of capture"
        self.source.start(self._queue)
        try:
            while True:
                if self._stop.is_set():
                    stopped_by = "stopped"
                    break
                if self.duration is not None and time.monotonic() - started >= self.duration:
                    stopped_by = "duration reached"
                    break
                try:
                    frame = self._queue.get(timeout=self.idle_advance)
                except queue.Empty:
                    if anchor is not None and self.clock_rate > 0:
                        # Trail real time by a second so the clock never overtakes a
                        # frame that is still on its way (it would reopen incidents).
                        now = anchor[0] + (time.monotonic() - anchor[1]) * self.clock_rate - 1.0
                        self.engine.advance(now)
                    if next_status is not None and time.monotonic() >= next_status and self.on_status:
                        self.on_status(self.engine)
                        next_status = time.monotonic() + (self.status_every or 0)
                    continue
                if frame is _END:
                    break
                ts, buf, linktype = frame
                if anchor is None:
                    anchor = (ts, time.monotonic())
                self.engine.process_frame(ts, buf, linktype)
                if next_status is not None and time.monotonic() >= next_status and self.on_status:
                    self.on_status(self.engine)
                    next_status = time.monotonic() + (self.status_every or 0)
        finally:
            self.source.stop()
            self._drain()
            self.source.finish()
        error = self.source.error()
        result = self.engine.finish()
        return SessionResult(result, self.source.summary(), time.monotonic() - started, stopped_by, error)

    def _drain(self) -> None:
        """Process frames still queued after stop (tcpdump flushes on SIGINT), until the end sentinel."""
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                frame = self._queue.get(timeout=0.5)
            except queue.Empty:
                return
            if frame is _END:
                return
            ts, buf, linktype = frame
            self.engine.process_frame(ts, buf, linktype)
