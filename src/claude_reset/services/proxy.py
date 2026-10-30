"""Private proxy draft; only fixed outcome labels cross the reporting boundary."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from .. import config
from ..backend import install as backend_install
from ..errors import SafetyError, error_kind
from ..model.records import present
from ..model.status import Backend, Measurement, Proxy
from ..network import connections, remote_backend
from ..network.probe import Probe

__all__ = ['ENGINE_STATUS', 'LocalBackendDraft', 'ProxyDraft', 'ProxyResult', 'check_saved', 'import_vless',
           'install_engine', 'remove_backend']


@dataclass(frozen=True)
class ProxyResult:
    """How a proxy or engine step ended: a fixed status, never an address, a path or an error text.

    clients_changed and selected are False where the step reports them (the Claude clients were not touched, an
    imported profile is not selected); error_type names an unexpected error. None: the step does not report it."""
    status: Proxy
    profile_id: str | None = None
    clients_changed: bool | None = None
    selected: bool | None = None
    error_type: str | None = None

    def to_json(self) -> dict:
        return present(status=self.status, profile_id=self.profile_id, clients_changed=self.clients_changed,
                       selected=self.selected, error_type=self.error_type)


# The step's own status for each status of the engine installer.
ENGINE_STATUS = MappingProxyType({
    Backend.INSTALLED: Proxy.ENGINE_INSTALLED,
    Backend.INSTALLED_NEEDS_ATTENTION: Proxy.ENGINE_NEEDS_ATTENTION,
    Backend.NOT_STARTED: Proxy.ENGINE_NOT_STARTED,
})


class ProxyDraft:
    def __init__(self, host, port, username='', password='', *, proxy_type='socks5', probe: Probe = Probe()):
        self.probe = probe
        try:
            self.proxy_type = proxy_type
            self.profile = remote_backend.validate(dict(
                schema=1, adapter=remote_backend.ADAPTERS[proxy_type], host=host.strip(),
                port=int(port), username=username, password=password))
        except (KeyError, ValueError, TypeError, SafetyError):
            raise SafetyError('Check the public IPv4, the port and the login and password', code='proxy_fields') from None
        self.expected = None

    def check(self) -> ProxyResult:
        self.expected = None
        try:
            if self.probe.reachable(self.profile).get('status') != Measurement.REACHABLE:
                return ProxyResult(Proxy.PROXY_UNREACHABLE)
            if not self.probe.handshake(self.profile).get('ok'):
                return ProxyResult(Proxy.PROXY_LOGIN_OR_CONNECT_REFUSED)
            measured = self.probe.measure_exit(self.profile)
            if measured.get('status') != Measurement.MEASURED:
                return ProxyResult(Proxy.PROXY_EXIT_UNAVAILABLE)
            connection = connections.validate(dict(schema=1, local_proxy=config.BACKEND_URL,
                router_proxy=None, expected_exit_ips=[measured['exit_ip']]))
            self.expected = connection
            return ProxyResult(Proxy.PROXY_CHECKED)
        except Exception as exc:
            return ProxyResult(Proxy.PROXY_CHECK_FAILED, error_type=error_kind(exc))

    def save(self, paths, *, confirmed: bool = False) -> ProxyResult:
        if not confirmed or self.expected is None:
            return ProxyResult(Proxy.PROXY_CONFIRMATION_REQUIRED)
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
        return ProxyResult(Proxy.PROXY_SAVED, clients_changed=False)


class LocalBackendDraft:
    """Recheck an installed local VLESS backend without selecting an imported profile."""
    def __init__(self, paths, *, first=False, probe: Probe = Probe()):
        # first: right after the engine install, when no expected exit has been saved yet.
        self.paths, self.first, self.probe = paths, first, probe
        self.expected = None

    def check(self) -> ProxyResult:
        self.expected = None
        try:
            current = connections.load(self.paths)
            if current is None and self.first:
                current = dict(schema=1, local_proxy=config.BACKEND_URL, router_proxy=None, expected_exit_ips=[])
            if current is None or current['local_proxy'] != config.BACKEND_URL or current['router_proxy'] is not None:
                return ProxyResult(Proxy.PROXY_CONFIRMATION_REQUIRED)
            if not self.probe.backend_status(self.paths).get('passed'):
                return ProxyResult(Proxy.PROXY_UNREACHABLE)
            measured = self.probe.measure_local(config.BACKEND_URL)
            if measured.get('status') != Measurement.MEASURED:
                return ProxyResult(Proxy.PROXY_EXIT_UNAVAILABLE)
            self.expected = connections.validate(dict(current, expected_exit_ips=[measured['exit_ip']]))
            return ProxyResult(Proxy.PROXY_CHECKED)
        except Exception as exc:
            return ProxyResult(Proxy.PROXY_CHECK_FAILED, error_type=error_kind(exc))

    def save(self, paths, *, confirmed: bool = False) -> ProxyResult:
        if not confirmed or self.expected is None:
            return ProxyResult(Proxy.PROXY_CONFIRMATION_REQUIRED)
        connections.save(paths, self.expected)
        return ProxyResult(Proxy.PROXY_SAVED, clients_changed=False)


def import_vless(paths, file: Path) -> ProxyResult:
    """Import through the existing inactive backend; keep paths/errors private."""
    from ..backend.profiles import import_profile
    try:
        result = import_profile(paths, file)
        return ProxyResult(Proxy.VLESS_IMPORTED, profile_id=result['profile_id'], clients_changed=False,
                           selected=False)
    except Exception as exc:
        return ProxyResult(Proxy.VLESS_IMPORT_REFUSED, error_type=error_kind(exc))


def install_engine(paths, profile_file: Path, archive: Path | None = None, *,
                   install=backend_install.install) -> ProxyResult:
    """Install the local VLESS+Reality engine task; the installer's error text (paths) stays private."""
    try:
        if remote_backend.load(paths) is not None:
            return ProxyResult(Proxy.ENGINE_REMOTE_PROFILE_SAVED)
        report = install(paths, profile_file, archive=archive)
    except Exception as exc:
        return ProxyResult(Proxy.ENGINE_INSTALL_FAILED, error_type=error_kind(exc))
    return ProxyResult(ENGINE_STATUS.get(report.get('status'), Proxy.ENGINE_INSTALL_FAILED))


def remove_backend(paths, *, remove=backend_install.remove, remote_remove=remote_backend.remove) -> ProxyResult:
    """Remove the engine task and a saved remote proxy profile; refused while the L1 relay is open."""
    try:
        report = remove(paths)
        if report.get('status') != Backend.REMOVED:
            return ProxyResult(Proxy.BACKEND_REMOVE_REFUSED)
        if not remote_remove(paths):
            return ProxyResult(Proxy.BACKEND_REMOVE_REFUSED)
    except Exception as exc:
        return ProxyResult(Proxy.BACKEND_REMOVE_REFUSED, error_type=error_kind(exc))
    return ProxyResult(Proxy.BACKEND_REMOVED)


def check_saved(paths, *, probe: Probe = Probe()) -> tuple[ProxyDraft | LocalBackendDraft | None, ProxyResult]:
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
    except Exception as exc:
        return None, ProxyResult(Proxy.PROXY_CHECK_FAILED, error_type=error_kind(exc))
