"""Private proxy draft; only fixed outcome labels cross the reporting boundary."""
from . import connections, remote_backend
from .safeio import SafetyError


class ProxyDraft:
    def __init__(self, host, port, username='', password='', *, proxy_type='socks5'):
        try:
            self.proxy_type = proxy_type
            self.profile = remote_backend.validate(dict(
                schema=1, adapter=remote_backend.ADAPTERS[proxy_type], host=host.strip(),
                port=int(port), username=username, password=password))
        except (KeyError, ValueError, TypeError, SafetyError):
            raise SafetyError('Проверьте публичный IPv4, порт и пару логин/пароль.') from None
        self.expected = None

    def check(self):
        self.expected = None
        try:
            if remote_backend.reachable(self.profile).get('status') != 'reachable':
                return {'status': 'proxy_unreachable'}
            if not remote_backend.handshake_test(self.profile).get('ok'):
                return {'status': 'proxy_login_or_connect_refused'}
            measured = remote_backend.measure_exit(self.profile)
            if measured.get('status') != 'measured':
                return {'status': 'proxy_exit_unavailable'}
            connection = connections.validate(dict(schema=1, local_proxy='http://127.0.0.1:25080',
                router_proxy=None, expected_exit_ips=[measured['exit_ip']]))
            self.expected = connection
            return {'status': 'proxy_checked'}
        except Exception:
            return {'status': 'proxy_check_failed'}

    def save(self, paths, *, confirmed=False):
        if not confirmed or self.expected is None:
            return {'status': 'proxy_confirmation_required'}
        # Existing mutation serialization and DPAPI are reused unchanged. The proxy and its exit are one pair:
        # if the exit cannot be written, the previous proxy file is put back byte for byte (or removed).
        from .safeio import atomic_bytes
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
        return {'status': 'proxy_saved', 'clients_changed': False}


class LocalBackendDraft:
    """Recheck an installed local VLESS backend without selecting an imported profile."""
    def __init__(self, paths, *, first=False):
        # first: right after the engine install, when no expected exit has been saved yet.
        self.paths, self.first = paths, first
        self.expected = None

    def check(self):
        from . import netguard
        self.expected = None
        try:
            current = connections.load(self.paths)
            if current is None and self.first:
                current = dict(schema=1, local_proxy=netguard.PROXY_URL, router_proxy=None, expected_exit_ips=[])
            if current is None or current['local_proxy'] != netguard.PROXY_URL or current['router_proxy'] is not None:
                return {'status': 'proxy_confirmation_required'}
            if not netguard.status(self.paths).get('passed'):
                return {'status': 'proxy_unreachable'}
            measured = connections.measure(netguard.PROXY_URL)
            if measured.get('status') != 'measured':
                return {'status': 'proxy_exit_unavailable'}
            self.expected = connections.validate(dict(current, expected_exit_ips=[measured['exit_ip']]))
            return {'status': 'proxy_checked'}
        except Exception:
            return {'status': 'proxy_check_failed'}

    def save(self, paths, *, confirmed=False):
        if not confirmed or self.expected is None:
            return {'status': 'proxy_confirmation_required'}
        connections.save(paths, self.expected)
        return {'status': 'proxy_saved', 'clients_changed': False}


def import_vless(paths, file):
    """Import through the existing inactive backend; keep paths/errors private."""
    from .backend_profiles import import_profile
    try:
        result = import_profile(paths, file)
        return {'status': 'vless_imported', 'profile_id': result['profile_id'],
                'clients_changed': False, 'selected': False}
    except Exception:
        return {'status': 'vless_import_refused'}


def install_engine(paths, profile_file, archive=None, *, install=None):
    """Install the local VLESS+Reality engine task; the installer's error text (paths) stays private."""
    from . import backend_install, remote_backend
    try:
        if remote_backend.load(paths) is not None:
            return {'status': 'engine_remote_profile_saved'}
        report = (install or backend_install.install)(paths, profile_file, archive=archive)
    except Exception:
        return {'status': 'engine_install_failed'}
    return {'status': {'installed': 'engine_installed', 'installed_needs_attention': 'engine_needs_attention',
                       'not_started': 'engine_not_started'}.get(report.get('status'), 'engine_install_failed')}


def remove_backend(paths, *, remove=None, remote_remove=None):
    """Remove the engine task and a saved remote proxy profile; refused while the L1 relay is open."""
    from . import backend_install, remote_backend
    try:
        report = (remove or backend_install.remove)(paths)
        if report.get('status') != 'removed':
            return {'status': 'backend_remove_refused'}
        if not (remote_remove or remote_backend.remove)(paths):
            return {'status': 'backend_remove_refused'}
    except Exception:
        return {'status': 'backend_remove_refused'}
    return {'status': 'backend_removed'}
