import os
import socket
import pytest
from claude_reset.tcp_inventory import listeners
from claude_reset.safeio import SafetyError


@pytest.mark.parametrize('family,address', [(socket.AF_INET,'127.0.0.1'),(socket.AF_INET6,'::1')])
def test_native_listener_inventory_binds_real_owner_and_disappears_after_close(family,address):
    with socket.socket(family,socket.SOCK_STREAM) as server:
        if family == socket.AF_INET6: server.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
        server.bind((address,0)); server.listen(1); port = server.getsockname()[1]
        assert (port,address,os.getpid()) in listeners([port])
    assert (port,address,os.getpid()) not in listeners([port])


@pytest.mark.parametrize('ports', [None,[True],[0],['1080'],[65536]])
def test_reject_unknown_port_scope(ports):
    with pytest.raises(SafetyError): listeners(ports)
