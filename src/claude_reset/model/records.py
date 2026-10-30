"""Shapes of the JSON documents the program stores or passes between its own processes.

Each shape is a TypedDict: its fields and their types, for readers and type checkers. `exact` checks a decoded
document against its shape at run time, and each validator then checks the values. Documents stay plain JSON
values, so the stored bytes and the hashes computed over them are unchanged.
"""
from __future__ import annotations
from typing import Literal, TypedDict
from collections.abc import Iterable

__all__ = ['BackendSpec', 'BrowserMeasurement', 'Claim', 'ConnectionProfile', 'EngineFile', 'EngineProfile',
           'GatewayProfile', 'Observation', 'PayloadFile', 'RemoteProxy', 'RequestInventory', 'SchedulerCount',
           'StateSelection', 'exact']


def exact(value: object, shape: type | Iterable[str]) -> bool:
    """True when value is a dict with exactly the fields of shape: a TypedDict or a collection of names."""
    keys = getattr(shape, '__required_keys__', None)
    return isinstance(value, dict) and value.keys() == (keys if keys is not None else frozenset(shape))


class StateSelection(TypedDict):
    """Which folder holds the program's state (the selection file next to the default state)."""
    schema: Literal[1]
    state_root: str


class ConnectionProfile(TypedDict):
    """The proxy Claude goes through and the exit addresses it must show."""
    schema: Literal[1]
    local_proxy: str
    router_proxy: str | None
    expected_exit_ips: list[str]


class RemoteProxy(TypedDict):
    """A SOCKS5 or HTTP proxy, saved with DPAPI."""
    schema: Literal[1]
    adapter: str
    host: str
    port: int
    username: str
    password: str


class EngineFile(TypedDict):
    """The tunnel engine binary, pinned by its hash."""
    engine_path: str
    engine_sha256: str


class EngineProfile(EngineFile):
    """An imported VLESS+Reality engine profile; inactive until the engine is installed with it."""
    schema: Literal[1]
    adapter: str
    engine_version: str
    config: dict


class GatewayProfile(EngineFile):
    """What the gateway service may start and which processes it trusts in this session."""
    schema: Literal[2]
    protocol: Literal['http', 'socks5']
    backend_port: int
    listen_port: int
    engine_pid: int
    engine_start_utc_ticks: int
    engine_config_path: str
    engine_config_sha256: str
    generation: str
    controller_pid: int
    controller_start_utc_ticks: int
    controller_path: str
    controller_sha256: str


class BackendSpec(TypedDict):
    """The installed backend service: its binaries, ports, peer and expected exits."""
    schema: Literal[1]
    profile_id: str
    engine_version: str
    engine_sha256: str
    engine_config_sha256: str
    runtime_sha256: str
    gateway_sha256: str
    peer_address: str
    peer_port: int
    backend_port: int
    gateway_port: int
    expected_exit_ips: list[str]


class PayloadFile(TypedDict):
    """One file of the installed payload, pinned by hash and size."""
    sha256: str
    bytes: int


class BrowserMeasurement(TypedDict):
    """What the loopback page measured in the selected browser."""
    timezone: str
    offset_minutes: int
    languages: list[str]
    geolocation: Literal['granted', 'denied', 'prompt', 'unavailable']


class Observation(TypedDict):
    """One network connection seen by the privacy observer."""
    t: int
    host: str
    port: int


class Claim(TypedDict):
    """Ownership of the single mutation in progress (the pending file)."""
    schema: Literal[2]
    operation: str
    owner_id: str
    state_root: str


class RequestInventory(TypedDict):
    """The elevation requests one claim has issued."""
    schema: Literal[1]
    claim: Claim
    requests: list


class SchedulerCount(TypedDict):
    """How often the scheduler was asked to run one elevation request."""
    schema: Literal[1]
    request: dict
    attempts: int
