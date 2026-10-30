"""Read TCP listener ownership without PowerShell or network requests."""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
import socket
from .api import Library
from ..errors import SafetyError
from collections.abc import Collection

__all__ = ['listeners']


class Row4(C.Structure):
    _fields_ = [(name,W.DWORD) for name in ('state','local_address','local_port','remote_address','remote_port','pid')]


class Row6(C.Structure):
    _fields_ = [('local_address',C.c_ubyte*16),('local_scope',W.DWORD),('local_port',W.DWORD),
                ('remote_address',C.c_ubyte*16),('remote_scope',W.DWORD),('remote_port',W.DWORD),
                ('state',W.DWORD),('pid',W.DWORD)]


def listeners(ports: Collection[int]) -> list[tuple[int, str, int]]:
    if not isinstance(ports,(tuple,list,set)) or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
        raise SafetyError('Explicit TCP ports required')
    api = Library('iphlpapi')
    rows = []
    for family, row_type, row_size in ((socket.AF_INET,Row4,24),(socket.AF_INET6,Row6,56)):
        if C.sizeof(row_type) != row_size:
            raise SafetyError('Unsupported TCP table layout')
        for attempt in range(3):
            size = W.DWORD()
            result = api.GetExtendedTcpTable(None,C.byref(size),False,family,3,0)
            if result not in (0,122) or not 4 <= size.value <= 16777216:
                raise SafetyError('TCP listener table unavailable')
            buffer = C.create_string_buffer(size.value)
            result = api.GetExtendedTcpTable(buffer,C.byref(size),False,family,3,0)
            if result == 122:
                continue
            if result:
                raise SafetyError('Cannot read TCP listener table')
            count = W.DWORD.from_buffer(buffer).value
            if 4 + count*row_size > len(buffer):
                raise SafetyError('Invalid TCP listener table size')
            for index in range(count):
                row = row_type.from_buffer(buffer,4+index*row_size)
                port = socket.ntohs(row.local_port & 0xffff)
                if port not in ports:
                    continue
                address = (row.local_address.to_bytes(4,'little') if family == socket.AF_INET else bytes(row.local_address))
                rows.append((port,socket.inet_ntop(family,address),int(row.pid)))
            break
        else:
            raise SafetyError('TCP listener table remained unstable')
    return rows
