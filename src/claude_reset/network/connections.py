"""Explicit proxy profiles and bounded egress measurements, never a tunnel certificate.

No default/system proxy, local destination DNS, redirects, router administration,
network settings or client sessions are used. Selection is diagnostic until an
enforcement backend binds it to the protected applications.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

from ..errors import SafetyError
from ..safeio import atomic_bytes, guarded
from ..windows.system import DPAPI
from ..elevation.claims import serialized_effect
from .. import config
from .. import layout
from ..model.status import Measurement
from ..model.records import ConnectionProfile, exact
from ..model.notes import Note
from ..model.ids import utc_now

MAX_PROFILE = 16384


def endpoint(value):
    """Numeric addresses avoid implicit DNS and ambiguous localhost resolution."""
    try:
        if not isinstance(value, str) or len(value) > 512 or any(c.isspace() for c in value):
            raise ValueError()
        url = urlsplit(value)
        address = ipaddress.ip_address(url.hostname)
        if (url.scheme not in ('http', 'socks5') or url.username is not None or url.password is not None
                or url.path or url.query or url.fragment or not url.port or '%' in url.netloc
                or address.is_unspecified or address.is_multicast):
            raise ValueError()
        host = f'[{address}]' if address.version == 6 else str(address)
        if value != f'{url.scheme}://{host}:{url.port}':
            raise ValueError()
        return url.scheme, str(address), url.port
    except (ValueError, TypeError, AttributeError):
        raise SafetyError('Proxy: use http://IP:port or socks5://IP:port, without credentials, path or DNS name') from None


def validate(profile):
    try:
        if not exact(profile, ConnectionProfile):
            raise ValueError()
        if type(profile['schema']) is not int or profile['schema'] != 1:
            raise ValueError()
        _, local, _ = endpoint(profile['local_proxy'])
        if not ipaddress.ip_address(local).is_loopback:
            raise SafetyError('Local proxy must listen on a numeric loopback address')
        if profile['router_proxy'] is not None:
            endpoint(profile['router_proxy'])
            if profile['router_proxy'] == profile['local_proxy']:
                raise SafetyError('Router and local proxy must be different endpoints')
        ips = profile['expected_exit_ips']
        if not isinstance(ips, list) or not 1 <= len(ips) <= 16 or any(not isinstance(ip, str) for ip in ips):
            raise ValueError()
        normalized = []
        for value in ips:
            ip = ipaddress.ip_address(value)
            if '%' in value or not ip.is_global or str(ip) != value:
                raise ValueError()
            normalized.append(str(ip))
        if len(set(normalized)) != len(normalized):
            raise ValueError()
        return dict(profile, expected_exit_ips=normalized)
    except (ValueError, TypeError, KeyError):
        raise SafetyError('Connection profile requires schema 1 and 1–16 distinct public exit IP addresses') from None


@serialized_effect('connection_save', succeeded=lambda row: row.get('status') == Measurement.CONNECTION_PROFILE_SAVED)
def save(paths, profile, *, crypto=None):
    profile = validate(profile)
    encrypted = (crypto or DPAPI()).encrypt(json.dumps(profile).encode('utf-8'))
    atomic_bytes(paths.state / layout.CONNECTION_PROFILE, encrypted, paths.state)
    return {'status': Measurement.CONNECTION_PROFILE_SAVED, 'passed': True, 'encrypted': True,
            'network_settings_changed': False, 'clients_reconfigured': False,
            'full_tunnel_verified': False}


@serialized_effect('connection_remove', succeeded=lambda value: value is True)
def remove(paths):
    """Delete the saved exit profile (L1 data). The source file the owner imported it from is never touched."""
    path = guarded(paths.state / layout.CONNECTION_PROFILE, paths.state)
    if path.exists():
        path.unlink()
    return not path.exists()


def load(paths, *, crypto=None):
    path = guarded(paths.state / layout.CONNECTION_PROFILE, paths.state)
    if not path.exists():
        return None
    if path.stat().st_size > MAX_PROFILE:
        raise SafetyError('Connection profile size limit exceeded')
    try:
        return validate(json.loads((crypto or DPAPI()).decrypt(path.read_bytes())))
    except (UnicodeError, ValueError):
        raise SafetyError('Connection profile is invalid') from None


def import_profile(paths, path):
    path = guarded(path, path.parent)
    if path.stat().st_size > MAX_PROFILE:
        raise SafetyError('Connection profile size limit exceeded')
    try:
        profile = json.loads(path.read_text('utf-8-sig'))
    except (UnicodeError, ValueError):
        raise SafetyError('Connection profile is invalid') from None
    return save(paths, profile)


def read_exact(stream, length, *, deadline=None):
    value = bytearray()
    while len(value) < length:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Proxy handshake timed out')
            stream.settimeout(remaining)
        part = stream.recv(length - len(value))
        if not part:
            raise OSError('Proxy closed the connection')
        value.extend(part)
    return bytes(value)


def connect(proxy, host, port=443, timeout=8):
    """HTTP CONNECT / SOCKS5 remote DNS. Never falls back to a direct socket."""
    scheme, address, proxy_port = endpoint(proxy)
    if host != config.CLAUDE_HOST or port != 443:
        raise SafetyError('Only the fixed HTTPS measurement destination is allowed')
    stream = socket.create_connection((address, proxy_port), timeout=timeout)
    deadline = time.monotonic() + timeout
    def receive(length):
        return read_exact(stream, length, deadline=deadline)
    try:
        if scheme == 'http':
            stream.sendall(f'CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n'.encode('ascii'))
            header = bytearray()
            while not header.endswith(b'\r\n\r\n') and len(header) < 8192:
                header.extend(receive(1))
            first = bytes(header).split(b'\r\n', 1)[0].split(b' ')
            if not header.endswith(b'\r\n\r\n') or len(first) < 2 or first[0] not in (b'HTTP/1.0', b'HTTP/1.1') or first[1] != b'200':
                raise OSError('HTTP proxy refused CONNECT')
        else:
            stream.sendall(b'\x05\x01\x00')
            if receive(2) != b'\x05\x00':
                raise OSError('SOCKS5 proxy requires unsupported authentication')
            name = host.encode('ascii')
            stream.sendall(b'\x05\x01\x00\x03' + bytes([len(name)]) + name + port.to_bytes(2, 'big'))
            reply = receive(4)
            if reply[:3] != b'\x05\x00\x00':
                raise OSError('SOCKS5 proxy refused CONNECT')
            if reply[3] == 1:
                length = 4
            elif reply[3] == 4:
                length = 16
            elif reply[3] == 3:
                length = receive(1)[0]
            else:
                raise OSError('Invalid SOCKS5 reply')
            receive(length + 2)
        stream.settimeout(timeout)
        return stream
    except BaseException:
        stream.close()
        raise


def measure(proxy):
    """Return the IP only to the in-memory caller; report builders redact it."""
    timer = None
    try:
        with connect(proxy, config.CLAUDE_HOST) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=config.CLAUDE_HOST) as stream:
                # Bound even a peer that drip-feeds an HTTP response within each
                # socket timeout. Never let a stalled diagnostic hang the UI.
                def expire():
                    try:
                        stream.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                timer = threading.Timer(12, expire)
                timer.daemon = True
                timer.start()
                stream.sendall((f'GET /cdn-cgi/trace HTTP/1.1\r\nHost: {config.CLAUDE_HOST}\r\n'
                                'User-Agent: ClaudeReset connection-check\r\nConnection: close\r\n\r\n').encode('ascii'))
                response = http.client.HTTPResponse(stream)
                response.begin()
                if response.status != 200:
                    return {'status': Measurement.HTTP_REFUSED, 'http_status': response.status}
                body = response.read(4097)
                if len(body) > 4096:
                    raise ValueError()
                fields = {}
                for line in body.decode('ascii').splitlines():
                    if '=' in line:
                        key, value = line.split('=', 1)
                        if key in fields:
                            raise ValueError()
                        fields[key] = value
                address = ipaddress.ip_address(fields['ip'])
                if not address.is_global:
                    raise ValueError()
                return {'status': Measurement.MEASURED, 'exit_ip': str(address), 'address_family': address.version}
    except (OSError, ValueError, KeyError, http.client.HTTPException) as exc:
        return {'status': Measurement.MEASUREMENT_FAILED, 'error_type': type(exc).__name__}
    finally:
        if timer is not None:
            timer.cancel()


def check(profile, *, include_router=False, measure_fn=None):
    profile = validate(profile)
    measure_fn = measure_fn or measure
    rows = {}
    selected = None
    # Explicit opt-in: an unknown incoming path is never probed by default.
    for source in ('router', 'local'):
        proxy = profile[f'{source}_proxy']
        if source == 'router' and (not include_router or not proxy):
            rows[source] = {'status': Measurement.NOT_REQUESTED if proxy else Measurement.NOT_CONFIGURED, 'exit_matches': False}
            continue
        result = measure_fn(proxy)
        matches = result.get('status') == Measurement.MEASURED and result.get('exit_ip') in profile['expected_exit_ips']
        rows[source] = {'status': Measurement.EXIT_MATCHES if matches else Measurement.EXIT_MISMATCH if result.get('status') == Measurement.MEASURED else Measurement.MEASUREMENT_FAILED,
                        'exit_matches': matches}
        if matches:
            selected = source
            break
    return {'schema': 1, 'utc': utc_now(),
            'status': Measurement.CANDIDATE_EXIT_VERIFIED if selected else Measurement.NO_VERIFIED_CANDIDATE,
            'passed': selected is not None, 'selected_candidate': selected, 'measurements': rows,
            'network_settings_changed': False, 'clients_reconfigured': False,
            'raw_addresses_saved': False, 'full_tunnel_verified': False,
            'limits': [Note('connection.limit.https_only'),
                       Note('connection.limit.tunnel'),
                       Note('connection.limit.open_clients'),
                       Note('connection.limit.router')]}
