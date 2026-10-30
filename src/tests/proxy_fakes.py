"""Scripted network checks for proxy drafts (services.proxy.Probe)."""
from scripted import Strict

REACHABLE = {'status': 'reachable'}
ACCEPTED = {'ok': True}


def measured(exit_ip):
    return {'status': 'measured', 'exit_ip': exit_ip}


class Probe(Strict):
    """reachable, handshake, measure_exit, measure_local, backend_status: a check without an answer fails the test."""


def working(exit_ip, **answers):
    """A probe of a proxy that answers, accepts the login and goes out through exit_ip."""
    return Probe(**{'reachable': REACHABLE, 'handshake': ACCEPTED, 'measure_exit': measured(exit_ip), **answers})
