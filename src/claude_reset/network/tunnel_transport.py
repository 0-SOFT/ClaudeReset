"""Provider-independent CONNECT gateway for a verified local HTTP/SOCKS5 backend.

Transport only: callers still need a Windows boundary and a lifetime-bound permit.
This module never certifies process coverage or creates firewall permissions.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import select
import socket
import time

from ..errors import SafetyError
from . import connections
from .relay import Relay

__all__ = ['ConnectRelay', 'TELEMETRY_SUFFIXES', 'destination', 'is_denied', 'open_stream']


# Vendors that receive client crash and log events; measured as destinations of Claude Desktop.
TELEMETRY_SUFFIXES = ('sentry.io', 'datadoghq.com')


def is_denied(host, suffixes):
    """Match whole labels only: `o1.ingest.sentry.io` and `sentry.io` match, `notsentry.io` does not."""
    return any(host == suffix or host.endswith('.' + suffix) for suffix in suffixes)


def destination(authority):
    if not isinstance(authority, str) or len(authority) > 260:
        raise SafetyError('Invalid CONNECT authority')
    if authority.startswith('['):
        match = re.fullmatch(r'\[([0-9A-Fa-f:]+)\]:([0-9]{1,5})', authority)
        if not match:
            raise SafetyError('Invalid IPv6 CONNECT authority')
        host = str(ipaddress.IPv6Address(match[1]))
        port = int(match[2])
    else:
        match = re.fullmatch(r'([A-Za-z0-9.-]+):([0-9]{1,5})', authority)
        if not match:
            raise SafetyError('Invalid CONNECT authority')
        host, port = match[1].lower(), int(match[2])
        if len(host) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in host.split('.')):
            raise SafetyError('Invalid destination hostname')
    if not 1 <= port <= 65535:
        raise SafetyError('Invalid destination port')
    return host, port


def read_header(stream, deadline):
    header = bytearray()
    while len(header) < 8192:
        header.extend(connections.read_exact(stream, 1, deadline=deadline))
        if header.endswith(b'\r\n\r\n'):
            return bytes(header)
    raise SafetyError('Proxy header size limit exceeded')


def open_stream(proxy, host, port, verify_peer, *, timeout=8, auth=None, remote=False):
    """Verify the accepted backend socket before sending even the destination name.

    `remote=True` allows one literal public HTTP/SOCKS5 peer instead of a loopback engine.
    `auth` is an optional (username, password) pair for Basic or RFC 1929 login.
    HTTP Basic is not encrypted on the proxy hop; destination TLS remains the caller's responsibility.
    """
    authority = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
    host, port = destination(authority)
    scheme, address, upstream_port = connections.endpoint(proxy)
    peer = ipaddress.ip_address(address)
    if remote:
        if scheme not in ('http', 'socks5') or not peer.is_global:
            raise SafetyError('A remote backend must be a literal public HTTP or SOCKS5 address')
    elif not peer.is_loopback:
        raise SafetyError('The gateway requires an explicitly bound local backend')
    authorization = ''
    if scheme == 'http' and auth is not None:
        if (not isinstance(auth, (tuple, list)) or len(auth) != 2
                or any(not isinstance(value, str) or not value or len(value) > 255
                       or not re.fullmatch(r'[\x21-\x7e]+', value) for value in auth)
                or ':' in auth[0]):
            raise SafetyError('Invalid HTTP proxy credentials')
        token = base64.b64encode(':'.join(auth).encode('ascii')).decode('ascii')
        authorization = f'Proxy-Authorization: Basic {token}\r\n'
    stream = socket.create_connection((address, upstream_port), timeout=timeout)
    deadline = time.monotonic() + timeout
    try:
        if verify_peer(stream) is not True:
            raise SafetyError('Backend socket owner is not verified')
        if scheme == 'http':
            stream.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{authorization}\r\n'.encode('ascii'))
            response = read_header(stream, deadline).split(b'\r\n', 1)[0].split(b' ')
            if len(response) < 2 or response[0] not in (b'HTTP/1.0', b'HTTP/1.1') or response[1] != b'200':
                raise SafetyError('HTTP backend refused CONNECT')
        else:
            if auth:
                stream.sendall(b'\x05\x02\x00\x02')
            else:
                stream.sendall(b'\x05\x01\x00')
            chosen = connections.read_exact(stream, 2, deadline=deadline)
            if chosen == b'\x05\x02' and auth:
                user, password = auth[0].encode('utf-8'), auth[1].encode('utf-8')
                stream.sendall(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
                if connections.read_exact(stream, 2, deadline=deadline) != b'\x01\x00':
                    raise SafetyError('SOCKS5 authentication failed')
            elif chosen != b'\x05\x00':
                raise SafetyError('SOCKS5 backend requires unsupported authentication')
            try:
                ip = ipaddress.ip_address(host)
                target = bytes([1 if ip.version == 4 else 4]) + ip.packed
            except ValueError:
                encoded = host.encode('ascii')
                target = b'\x03' + bytes([len(encoded)]) + encoded
            # Domain names are carried in SOCKS5; never resolve them on this PC.
            stream.sendall(b'\x05\x01\x00' + target + port.to_bytes(2, 'big'))
            reply = connections.read_exact(stream, 4, deadline=deadline)
            if reply[:3] != b'\x05\x00\x00':
                raise SafetyError('SOCKS5 backend refused CONNECT')
            if reply[3] == 1:
                length = 4
            elif reply[3] == 4:
                length = 16
            elif reply[3] == 3:
                length = connections.read_exact(stream, 1, deadline=deadline)[0]
                if not length:
                    raise SafetyError('Empty SOCKS5 reply address')
            else:
                raise SafetyError('Invalid SOCKS5 reply address')
            connections.read_exact(stream, length + 2, deadline=deadline)
        stream.settimeout(5)
        return stream
    except BaseException:
        stream.close()
        raise


class ConnectRelay(Relay):
    """HTTP CONNECT frontend; one selected backend, no direct or alternate route."""
    def __init__(self, proxy, verify_peer, *, port, remote=False, auth=None):
        _, address, _ = connections.endpoint(proxy)
        if remote:
            if not ipaddress.ip_address(address).is_global:
                raise SafetyError('A remote backend must be a literal public address')
        elif not ipaddress.ip_address(address).is_loopback:
            raise SafetyError('Backend must be local and independently constrained')
        self.remote, self.auth = remote, auth
        self.proxy = proxy
        super().__init__(None, verify_peer, port=port)

    measure = None  # optional Path: destination names only, for the privacy measurement pass
    deny = ()  # domain suffixes refused with 403 before the backend ever sees the name

    def note(self, host, port):
        path = self.measure
        if path is None:
            return
        try:
            with self.lock:
                if path.exists() and path.stat().st_size > 1_000_000:
                    return
                with open(path, 'a', encoding='ascii') as stream:
                    stream.write(json.dumps({'t': int(time.time()), 'host': host, 'port': port}) + chr(10))
        except (OSError, UnicodeError):
            pass

    def _pipe(self, client):
        upstream = None
        try:
            header = read_header(client, time.monotonic() + 5)
            lines = header[:-4].split(b'\r\n')
            fields = lines[0].split(b' ')
            if len(fields) != 3 or fields[0] != b'CONNECT' or fields[2] != b'HTTP/1.1':
                raise SafetyError('Only HTTP/1.1 CONNECT is supported')
            for line in lines[1:]:
                if b':' not in line or line[:1] in (b' ', b'\t') or any(c < 32 or c > 126 for c in line):
                    raise SafetyError('Invalid proxy header')
                key, value = line.split(b':', 1)
                if key.lower() in (b'transfer-encoding', b'content-length', b'proxy-authorization'):
                    raise SafetyError('CONNECT bodies and proxy credentials are unsupported')
            host, port = destination(fields[1].decode('ascii'))
            if self.stopped.is_set():
                return
            self.note(host, port)
            if is_denied(host, self.deny):
                client.sendall(b'HTTP/1.1 403 Forbidden\r\n\r\n')
                return
            upstream = open_stream(self.proxy, host, port, self.verify_peer, auth=self.auth, remote=self.remote)
            with self.lock:
                if self.stopped.is_set():
                    return
                self.clients.add(upstream)
            client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            while not self.stopped.is_set():
                readable, _, _ = select.select([client, upstream], [], [], .5)
                for source in readable:
                    data = source.recv(32768)
                    if not data or self.stopped.is_set():
                        return
                    (upstream if source is client else client).sendall(data)
        except (OSError, SafetyError, ValueError, UnicodeError):
            pass
        finally:
            with self.lock:
                for stream in (client, upstream):
                    if stream is not None:
                        self.clients.discard(stream)
                        try:
                            stream.close()
                        except OSError:
                            pass
            self.slots.release()
