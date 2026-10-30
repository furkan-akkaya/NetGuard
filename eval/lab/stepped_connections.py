"""Bounded successful TCP connections between the two owned lab VMs only.

Ubuntu: python3 stepped_connections.py server
Kali:   python3 stepped_connections.py client > exp15-load-r01.client.json
Start the live capture first. Repeat with fresh captures; never reuse a baseline.
"""

from __future__ import annotations

import argparse
import json
import socket
import time

CLIENT, SERVER, PORT = "10.77.0.10", "10.77.0.20", 9098
RATES = (1, 5, 10, 25)
PAYLOAD = b"NetGuard-owned-lab-load\n".ljust(512, b".")


def local_socket(address: str) -> socket.socket:
    sock = socket.socket()
    try:
        sock.bind((address, 0))
    except OSError:
        sock.close()
        raise SystemExit(f"Refusing: this host does not own lab address {address}") from None
    return sock


def phase(rate: float, seconds: int) -> dict[str, float | int]:
    started, successes, errors = time.monotonic(), 0, 0
    deadline = started + seconds
    due = started
    while time.monotonic() < deadline:
        time.sleep(max(0, due - time.monotonic()))
        if time.monotonic() >= deadline:
            break
        try:
            with socket.create_connection((SERVER, PORT), timeout=2, source_address=(CLIENT, 0)) as sock:
                sock.sendall(PAYLOAD)
                if sock.recv(2) != b"OK":
                    raise OSError("missing server acknowledgement")
            successes += 1
        except OSError:
            errors += 1
            if errors >= 5:
                raise SystemExit(
                    "Five failed connections: stop and inspect the capture; do not increase load"
                ) from None
        # No catch-up bursts after a slow iteration.
        due = max(due + 1 / rate, time.monotonic())
    elapsed = time.monotonic() - started
    return {
        "target_connections_s": rate,
        "elapsed_s": elapsed,
        "successful": successes,
        "errors": errors,
        "achieved_connections_s": successes / elapsed,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=["server", "client"])
    args = parser.parse_args()
    with local_socket(CLIENT if args.role == "client" else SERVER):
        pass
    if args.role == "client":
        results = [phase(0.2, 780)]  # 13 min: >=10 complete baseline intervals, any start offset
        for rate in RATES:
            results.append(phase(rate, 60))
        print(json.dumps({"kind": "controlled_live_load", "payload_bytes": len(PAYLOAD), "phases": results}, indent=2))
        return
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((SERVER, PORT))
        server.listen(64)
        server.settimeout(1)
        deadline = time.monotonic() + 1800
        print(f"Ready on {SERVER}:{PORT}; fixed 30 minute lifetime", flush=True)
        while time.monotonic() < deadline:
            try:
                sock, peer = server.accept()
            except TimeoutError:
                continue
            with sock:
                if peer[0] != CLIENT:
                    continue
                sock.settimeout(2)
                try:
                    remaining = len(PAYLOAD)
                    while remaining:
                        data = sock.recv(remaining)
                        if not data:
                            break
                        remaining -= len(data)
                    if not remaining:
                        sock.sendall(b"OK")
                except OSError:
                    continue


if __name__ == "__main__":
    main()
