"""Shapes of the JSON documents the program stores or passes between its own processes.

Each shape is a TypedDict: its fields and their types, for readers and type checkers. `exact` checks a decoded
document against its shape at run time, and each validator then checks the values. Documents stay plain JSON
values, so the stored bytes and the hashes computed over them are unchanged. `present` builds a document whose
optional keys are absent when they have no value.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Literal, TypedDict

__all__ = ['BrowserMeasurement', 'Claim', 'ConnectionProfile', 'EngineFile', 'EngineProfile',
           'Observation', 'RemoteProxy', 'RequestInventory', 'SchedulerCount',
           'StateSelection', 'exact', 'present']


def exact(value: object, shape: type | Iterable[str]) -> bool:
    """True when value is a dict with exactly the fields of shape: a TypedDict or a collection of names."""
    keys = getattr(shape, '__required_keys__', None)
    return isinstance(value, dict) and value.keys() == (keys if keys is not None else frozenset(shape))


def present(**fields: object) -> dict:
    """The given fields in their order, without those that are None: the optional keys a document does not have."""
    return {key: value for key, value in fields.items() if value is not None}


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
