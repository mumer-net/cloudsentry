"""Ground truth for the exposure check: try real TCP connections from this machine."""

from __future__ import annotations

import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# portquiz.net accepts connections on every TCP port, so it shows whether the local network
# lets these ports out at all. A campus network that blocks outbound 3389 would otherwise look
# like a security group that works.
PREFLIGHT_HOST = "portquiz.net"


def tcp_open(host: str, port: int, timeout: float = 3.0, tries: int = 2) -> bool:
    for _ in range(tries):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def my_public_ip() -> str:
    with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=10) as response:  # noqa: S310 (fixed https URL)
        return response.read().decode().strip()


def preflight(ports: tuple[int, ...]) -> dict[int, bool]:
    return {port: tcp_open(PREFLIGHT_HOST, port) for port in ports}


def probe(targets: list[tuple[str, int]]) -> dict[tuple[str, int], bool]:
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = pool.map(lambda target: tcp_open(*target), targets)
    return dict(zip(targets, results, strict=True))
