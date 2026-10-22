"""Server settings (command-line flags and environment), with secure defaults."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

from netguard.config import Config
from netguard.jobs import JobLimits

TOKEN_ENV = "NETGUARD_API_TOKEN"  # noqa: S105 - the variable name, not a secret
MIN_TOKEN_LENGTH = 16


class SettingsError(ValueError):
    pass


@dataclass
class ServerSettings:
    data_dir: Path
    host: str = "127.0.0.1"
    port: int = 8000
    token: str | None = None
    allow_remote_without_token: bool = False
    max_upload_bytes: int = 256 * 1024 * 1024
    max_storage_bytes: int = 10 * 1024 * 1024 * 1024  # all stored captures together
    max_pending_analyses: int = 100  # queued + running
    analysis_config: Config = field(default_factory=Config)
    jobs: JobLimits = field(default_factory=JobLimits)
    run_jobs: bool = True  # tests drive the runner themselves
    static_dir: Path | None = None  # dashboard bundle; default: the package's web/static
    # Host names (besides loopback and --host) clients may use, e.g. the name a
    # reverse proxy forwards. Anything else is refused (DNS rebinding defence).
    allowed_hosts: list[str] = field(default_factory=list)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "netguard.db"

    @property
    def captures_dir(self) -> Path:
        return self.data_dir / "captures"

    def validate(self) -> None:
        if self.token is not None and len(self.token) < MIN_TOKEN_LENGTH:
            raise SettingsError(f"{TOKEN_ENV} must be at least {MIN_TOKEN_LENGTH} characters")
        if not self.token and not _is_loopback(self.host) and not self.allow_remote_without_token:
            raise SettingsError(
                f"refusing to listen on {self.host} without an API token: set {TOKEN_ENV}, "
                "bind to 127.0.0.1, or pass --insecure-no-auth if another layer protects the API"
            )
        if self.max_upload_bytes <= 0 or self.max_storage_bytes <= 0 or self.max_pending_analyses <= 0:
            raise SettingsError("upload, storage and queue limits must be > 0")


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
