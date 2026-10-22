"""Measure peak memory under a spoofed-source SYN flood (every packet a new flow).

This is the worst case for the flow table and endpoint statistics: neither may
grow beyond its configured bound. Prints peak RSS and how many flows were evicted.

    uv run python benchmarks/flood_memory.py [packets]
"""

from __future__ import annotations

import resource
import sys
import time

from netguard.engine import Engine
from netguard.models import SYN, Packet


def main(n: int) -> None:
    engine = Engine()
    start = time.perf_counter()
    for i in range(n):
        src = f"{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}.7"
        engine.process(
            Packet(
                ts=1_000.0 + i * 1e-5,
                length=60,
                proto="tcp",
                src_ip=src,
                dst_ip="10.0.0.10",
                src_port=1024 + i % 60000,
                dst_port=80,
                tcp_flags=SYN,
                tcp_seq=i,
                payload_len=0,
            )
        )
    result = engine.finish()
    elapsed = time.perf_counter() - start
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    rss_mb = rss / 1024 / 1024 if sys.platform == "darwin" else rss / 1024  # bytes on macOS, KiB on Linux
    s = result.stats
    print(
        f"packets={n:,} flows={s.flows_total:,} evicted={s.flows_evicted:,} "
        f"endpoints_kept={len(s.endpoints):,} approximate={s.endpoints_approximate} "
        f"peak_rss={rss_mb:.0f}MB time={elapsed:.1f}s ({n / elapsed:,.0f} pkt/s, Packet objects, no decode)"
    )


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 500_000)
