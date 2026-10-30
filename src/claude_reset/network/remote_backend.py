"""A remote HTTP CONNECT or SOCKS5 proxy (optionally with username and password) as the L1 tunnel, without the sing-box engine.

The relay inside the controller connects to the proxy itself; the Windows deny rules for Claude are the
same as with the engine backend (Claude can reach only the loopback relay). The controller process is not
a protected client, so it needs no extra permit. Fail-closed rules kept: a literal public IPv4 peer (no DNS
name, so no name lookup outside the tunnel), no direct fallback, and the peer is probed before any deny is
installed. The profile is sealed with DPAPI for the current user.

Limit worth knowing: SOCKS5 is not encrypted between this PC and the proxy. The proxy (and the network in
between) can see the destination names that Claude asks for and the credentials' exchange; the content is
still TLS to the destination.
"""
import json
import re
import threading
from pathlib import Path
from types import MappingProxyType

from .. import config
from ..elevation.claims import serialized, serialized_effect
from ..errors import SafetyError, error_info, error_kind
from ..model.jsonc import strict_loads
from ..model.records import RemoteProxy, exact
from ..model.status import Backend, Measurement
from ..safeio import atomic_bytes, guarded
from ..windows.dpapi import DPAPI
from . import connections, exit_reachability
from .exit_reachability import public_address

__all__ = ['ADAPTER', 'ADAPTERS', 'FILE', 'HTTP_ADAPTER', 'auth_of', 'backend_kind', 'check_saved', 'decode',
           'handshake_test', 'install', 'load', 'make_relay', 'measure_exit', 'path_of', 'proxy_url', 'reachable',
           'remove', 'save', 'validate']

ADAPTER = 'socks5_remote_v1'
HTTP_ADAPTER = 'http_remote_v1'
ADAPTERS = MappingProxyType({'socks5': ADAPTER, 'http': HTTP_ADAPTER})
FILE = 'remote-socks5.dpapi'
LIMIT = 4096


def validate(profile):
    if not exact(profile, RemoteProxy) or profile['schema'] != 1 or profile['adapter'] not in ADAPTERS.values():
        raise SafetyError('Unsupported remote proxy profile: expected the fields schema, adapter, host, port, username, password')
    public_address(profile['host'], ipv4=True)
    if type(profile['port']) is not int or not 1 <= profile['port'] <= 65535:
        raise SafetyError('Invalid proxy port')
    user, password = profile['username'], profile['password']
    for value in (user, password):
        if not isinstance(value, str) or len(value.encode('utf-8')) > 255 or not re.fullmatch(r'[\x21-\x7e]*', value):
            raise SafetyError('Username and password must be printable ASCII without spaces, up to 255 bytes')
    if bool(user) != bool(password):
        raise SafetyError('Give both a username and a password, or neither')
    if profile['adapter'] == HTTP_ADAPTER and ':' in user:
        raise SafetyError('HTTP proxy username must not contain a colon')
    return profile


def decode(data):
    profile = strict_loads(data, limit=LIMIT, too_large='Remote proxy profile size limit exceeded',
                           invalid='Invalid remote proxy profile', encoding='utf-8-sig')
    try:
        return validate(profile)
    except (UnicodeError, ValueError, TypeError):
        raise SafetyError('Invalid remote proxy profile') from None


def proxy_url(profile):
    validate(profile)
    scheme = "http" if profile["adapter"] == HTTP_ADAPTER else "socks5"
    return f"{scheme}://{profile['host']}:{profile['port']}"


def backend_kind(profile):
    return 'remote_http' if profile['adapter'] == HTTP_ADAPTER else 'remote_socks5'


def auth_of(profile):
    return (profile['username'], profile['password']) if profile['username'] else None


def path_of(paths):
    return guarded(paths.state / FILE, paths.state)


@serialized_effect('remote_profile_save', succeeded=lambda value: value is None)
def save(paths, profile, *, crypto=DPAPI()):
    validate(profile)
    paths.state.mkdir(parents=True, exist_ok=True)
    atomic_bytes(path_of(paths), crypto.encrypt(json.dumps(profile, sort_keys=True).encode('utf-8')), paths.state)


def load(paths, *, crypto=DPAPI()):
    """The saved profile, or None when this PC does not use a remote proxy backend."""
    path = path_of(paths)
    if not path.exists():
        return None
    if path.stat().st_size > LIMIT * 4:
        raise SafetyError('Remote proxy profile is too large')
    return decode(crypto.decrypt(path.read_bytes()))


@serialized_effect('remote_profile_remove', succeeded=lambda value: value is True)
def remove(paths):
    path = path_of(paths)
    if path.exists():
        path.unlink()
    return not path.exists()


def reachable(profile, probe=exit_reachability.probe):
    return probe(profile['host'], profile['port'])


def make_relay(profile, *, port, verify_peer=lambda stream: True):
    from .tunnel_transport import ConnectRelay
    return ConnectRelay(proxy_url(profile), verify_peer, port=port, remote=True, auth=auth_of(profile))


def handshake_test(profile, host=config.CLAUDE_HOST, port=443):
    """One real proxy authentication and CONNECT through the proxy; the proxy's reply is never returned."""
    from .tunnel_transport import open_stream
    try:
        open_stream(proxy_url(profile), host, port, lambda stream: True, auth=auth_of(profile), remote=True).close()
        return {'ok': True}
    except SafetyError as exc:
        return {'ok': False, 'reason': str(exc)[:120]}
    except OSError as exc:
        return {'ok': False, 'reason': 'network: ' + error_kind(exc)}


def measure_exit(profile, *, measure=connections.measure):
    """Measure the exit address through a short-lived relay on an ephemeral loopback port.

    measure measures through a proxy URL."""
    relay = make_relay(profile, port=0)
    thread = threading.Thread(target=relay.serve, daemon=True)
    thread.start()
    try:
        return measure(config.loopback_url(relay.port))
    finally:
        relay.close()


@serialized('remote_backend_install', completed={Backend.INSTALLED, Backend.NOT_STARTED, Backend.NOT_INSTALLED}, nested=True)
def install(paths, profile_file, *, probe=exit_reachability.probe, test=handshake_test, measure=measure_exit):
    """Validate, check the peer, prove the login, seal the profile. No process, task, firewall rule or client is touched."""
    result = {'schema': 1, 'finished': False, 'action': 'backend_install', 'backend': 'remote_socks5', 'elevation_used': False,
              'firewall_changed': False, 'clients_changed': False, 'raw_addresses_saved': False}
    try:
        profile = decode(Path(profile_file).read_bytes())
        result['backend'] = backend_kind(profile)
        if load(paths) is not None:
            result.update(status=Backend.NOT_STARTED, reasons=['profile_exists: a remote proxy profile is already saved; remove it first'], finished=True)
            return result
        reach = reachable(profile, probe)
        result['peer'] = reach['status']
        if reach['status'] != Measurement.REACHABLE:
            result.update(status=Backend.NOT_INSTALLED, reason='peer_unreachable', finished=True)
            return result
        proof = test(profile)
        result['http_login_and_connect' if profile['adapter'] == HTTP_ADAPTER else 'socks5_login_and_connect'] = proof['ok']
        if not proof['ok']:
            result.update(status=Backend.NOT_INSTALLED, reason=proof.get('reason'), finished=True)
            return result
        save(paths, profile)
        measured = measure(profile)
        result['exit_measured'] = measured.get('status') == Measurement.MEASURED
        result['exit_address_family'] = measured.get('address_family')   # the address itself is never returned
        result['status'] = Backend.INSTALLED if result['exit_measured'] else Backend.INSTALLED_NEEDS_ATTENTION
    except Exception as exc:
        result.update(status=Backend.FAILED, error=error_info(exc))
    result['finished'] = True
    return result


def check_saved(paths, *, include_router=False, measure_remote=measure_exit, measure_local=connections.measure):
    """Check the saved connection; with a saved remote proxy the exit is measured through it.

    measure_remote measures through a remote proxy profile, measure_local through a proxy URL."""
    profile = connections.load(paths)
    if profile is None:
        raise SafetyError('Configure a connection profile first')
    remote = load(paths)
    if remote is not None:
        # A remote SOCKS5 backend has no loopback listener of its own; measure through a short-lived relay.
        return connections.check(profile, include_router=include_router,
                                 measure_fn=lambda proxy: measure_remote(remote))
    return connections.check(profile, include_router=include_router, measure_fn=measure_local)
