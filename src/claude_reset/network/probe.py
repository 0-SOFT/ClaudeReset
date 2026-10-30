"""The network checks around a proxy: is it reachable, does it accept the login, where does it go out.

Drafts of a proxy and the controller take a Probe; tests give them a scripted one instead of patching modules.
"""
from __future__ import annotations

from ..backend import location as backend_location
from . import brokered_dns, connections, remote_backend

__all__ = ['Probe']


class Probe:
    """The network checks of a proxy, each the same call the program made before: the port tests replace."""

    def reachable(self, profile: dict) -> dict:
        return remote_backend.reachable(profile)

    def handshake(self, profile: dict) -> dict:
        return remote_backend.handshake_test(profile)

    def measure_exit(self, profile: dict) -> dict:
        return remote_backend.measure_exit(profile)

    def measure_local(self, proxy_url: str) -> dict:
        return connections.measure(proxy_url)

    def backend_status(self, paths) -> dict:
        return backend_location.status(paths)

    def check(self, profile: dict) -> dict:
        """The saved exit profile measured through its proxies."""
        return connections.check(profile)

    def coverage(self) -> dict:
        """Whether the delegated traffic of the clients is covered (brokered_dns.coverage_gate)."""
        return brokered_dns.coverage_gate()
