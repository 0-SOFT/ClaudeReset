"""Network guard for the narrow proxy tests; applied before test bodies."""
import ipaddress
import socket
import pytest


@pytest.fixture(autouse=True)
def loopback_only(monkeypatch):
    connect, connect_ex, resolve = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo

    def check(host):
        assert ipaddress.ip_address(host).is_loopback, 'External network forbidden in proxy tests'

    def guarded_connect(stream, address):
        check(address[0])
        return connect(stream, address)

    def guarded_connect_ex(stream, address):
        check(address[0])
        return connect_ex(stream, address)

    def guarded_resolve(host, *args, **kwargs):
        check(host)
        return resolve(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, 'connect', guarded_connect)
    monkeypatch.setattr(socket.socket, 'connect_ex', guarded_connect_ex)
    monkeypatch.setattr(socket, 'getaddrinfo', guarded_resolve)
