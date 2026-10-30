"""Private proxy draft; only fixed outcome labels cross the reporting boundary."""
from ..network import connections, remote_backend
from ..errors import SafetyError
from .. import config
from ..model.status import Backend, Measurement, Proxy
from ..network.probe import Probe
from pathlib import Path

__all__ = ['LocalBackendDraft', 'ProxyDraft', 'check_saved', 'import_vless', 'install_engine',
           'remove_backend']


class ProxyDraft:
    def __init__(self, host, port, username='', password='', *, proxy_type='socks5', probe=None):
        self.probe = probe or Probe()
        try:
            self.proxy_type = proxy_type
            self.profile = remote_backend.validate(dict(
                schema=1, adapter=remote_backend.ADAPTERS[proxy_type], host=host.strip(),
                port=int(port), username=username, password=password))
        except (KeyError, ValueError, TypeError, SafetyError):
            raise SafetyError('Check the public IPv4, the port and the login and password', code='proxy_fields') from None
        self.expected = None

    def check(self) -> dict:
        self.expected = None
        try:
            if self.probe.reachable(self.profile).get('status') != Measurement.REACHABLE:
                return {'status': Proxy.PROXY_UNREACHABLE}
            if not self.probe.handshake(self.profile).get('ok'):
                return {'status': Proxy.PROXY_LOGIN_OR_CONNECT_REFUSED}
            measured = self.probe.measure_exit(self.profile)
            if measured.get('status') != Measurement.MEASURED:
                return {'status': Proxy.PROXY_EXIT_UNAVAILABLE}
            connection = connections.validate(dict(schema=1, local_proxy=config.BACKEND_URL,
                router_proxy=None, expected_exit_ips=[measured['exit_ip']]))
            self.expected = connection
            return {'status': Proxy.PROXY_CHECKED}
        except Exception:
            return {'status': Proxy.PROXY_CHECK_FAILED}

    def save(self, paths, *, confirmed: bool = False) -> dict:
        if not confirmed or self.expected is None:
            return {'status': Proxy.PROXY_CONFIRMATION_REQUIRED}
        # Existing mutation serialization and DPAPI are reused unchanged. The proxy and its exit are one pair:
        # if the exit cannot be written, the previous proxy file is put back byte for byte (or removed).
        from ..safeio import atomic_bytes
        path = remote_backend.path_of(paths)
        previous = path.read_bytes() if path.is_file() else None
        remote_backend.save(paths, self.profile)
        try:
            connections.save(paths, self.expected)
        except BaseException:
            if previous is None:
                path.unlink(missing_ok=True)
            else:
                atomic_bytes(path, previous, paths.state)
            raise
        return {'status': Proxy.PROXY_SAVED, 'clients_changed': False}


class LocalBackendDraft:
    """Recheck an installed local VLESS backend without selecting an imported profile."""
    def __init__(self, paths, *, first=False, probe=None):
        # first: right after the engine install, when no expected exit has been saved yet.
        self.paths, self.first, self.probe = paths, first, probe or Probe()
        self.expected = None

    def check(self) -> dict:
        self.expected = None
        try:
            current = connections.load(self.paths)
            if current is None and self.first:
                current = dict(schema=1, local_proxy=config.BACKEND_URL, router_proxy=None, expected_exit_ips=[])
            if current is None or current['local_proxy'] != config.BACKEND_URL or current['router_proxy'] is not None:
                return {'status': Proxy.PROXY_CONFIRMATION_REQUIRED}
            if not self.probe.backend_status(self.paths).get('passed'):
                return {'status': Proxy.PROXY_UNREACHABLE}
            measured = self.probe.measure_local(config.BACKEND_URL)
            if measured.get('status') != Measurement.MEASURED:
                return {'status': Proxy.PROXY_EXIT_UNAVAILABLE}
            self.expected = connections.validate(dict(current, expected_exit_ips=[measured['exit_ip']]))
            return {'status': Proxy.PROXY_CHECKED}
        except Exception:
            return {'status': Proxy.PROXY_CHECK_FAILED}

    def save(self, paths, *, confirmed: bool = False) -> dict:
        if not confirmed or self.expected is None:
            return {'status': Proxy.PROXY_CONFIRMATION_REQUIRED}
        connections.save(paths, self.expected)
        return {'status': Proxy.PROXY_SAVED, 'clients_changed': False}


def import_vless(paths, file: Path) -> dict:
    """Import through the existing inactive backend; keep paths/errors private."""
    from ..backend.profiles import import_profile
    try:
        result = import_profile(paths, file)
        return {'status': Proxy.VLESS_IMPORTED, 'profile_id': result['profile_id'],
                'clients_changed': False, 'selected': False}
    except Exception:
        return {'status': Proxy.VLESS_IMPORT_REFUSED}


def install_engine(paths, profile_file: Path, archive: Path | None = None, *, install=None) -> dict:
    """Install the local VLESS+Reality engine task; the installer's error text (paths) stays private."""
    from ..backend import install as backend_install
    from ..network import remote_backend
    try:
        if remote_backend.load(paths) is not None:
            return {'status': Proxy.ENGINE_REMOTE_PROFILE_SAVED}
        report = (install or backend_install.install)(paths, profile_file, archive=archive)
    except Exception:
        return {'status': Proxy.ENGINE_INSTALL_FAILED}
    return {'status': {Backend.INSTALLED: Proxy.ENGINE_INSTALLED, Backend.INSTALLED_NEEDS_ATTENTION: Proxy.ENGINE_NEEDS_ATTENTION,
                       Backend.NOT_STARTED: Proxy.ENGINE_NOT_STARTED}.get(report.get('status'), Proxy.ENGINE_INSTALL_FAILED)}


def remove_backend(paths, *, remove=None, remote_remove=None) -> dict:
    """Remove the engine task and a saved remote proxy profile; refused while the L1 relay is open."""
    from ..backend import install as backend_install
    from ..network import remote_backend
    try:
        report = (remove or backend_install.remove)(paths)
        if report.get('status') != Backend.REMOVED:
            return {'status': Proxy.BACKEND_REMOVE_REFUSED}
        if not (remote_remove or remote_backend.remove)(paths):
            return {'status': Proxy.BACKEND_REMOVE_REFUSED}
    except Exception:
        return {'status': Proxy.BACKEND_REMOVE_REFUSED}
    return {'status': Proxy.BACKEND_REMOVED}


def check_saved(paths, *, probe: Probe | None = None) -> tuple:
    """Check the saved proxy again: a private draft, and the fixed outcome of its check."""
    try:
        profile = remote_backend.load(paths)
        if profile is None:
            draft = LocalBackendDraft(paths, probe=probe)
            return draft, draft.check()
        draft = ProxyDraft(**{k: profile[k] for k in ('host', 'port', 'username', 'password')},
                           proxy_type='http' if profile.get('adapter') == remote_backend.HTTP_ADAPTER else 'socks5',
                           probe=probe)
        return draft, draft.check()
    except Exception:
        return None, {'status': Proxy.PROXY_CHECK_FAILED}
