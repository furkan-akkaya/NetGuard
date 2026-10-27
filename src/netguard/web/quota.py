"""Storage quota with reservations for uploads in progress (THREAT_MODEL.md).

Checking "stored bytes < quota" once at the start of an upload is not enough:
two uploads that start together both see the same free space and together
store more than the quota. Every upload therefore reserves the bytes it
receives, chunk by chunk, before writing them. A reservation is released once
the capture row is stored (from then on it counts as used space) or when the
upload fails, is rejected or the client disconnects.

The ledger lives in the server process. ``netguard serve`` runs one process;
several processes sharing a data directory would each enforce the quota alone.
"""

from __future__ import annotations

import threading
from collections.abc import Callable


class StorageQuota:
    def __init__(self, limit: int, used: Callable[[], int]) -> None:
        self.limit = limit
        self._used = used  # bytes of stored captures
        self._lock = threading.Lock()
        self.reserved = 0

    def available(self) -> int:
        with self._lock:
            return self.limit - self._used() - self.reserved

    def reserve(self, n: int) -> bool:
        """Reserve ``n`` more bytes if stored + reserved stays within the quota."""
        with self._lock:
            if self._used() + self.reserved + n > self.limit:
                return False
            self.reserved += n
            return True

    def release(self, n: int) -> None:
        with self._lock:
            self.reserved -= n
