"""Read-only readiness check for installing or running L1 on this PC.

Changes nothing, starts no client and makes no network request. `evaluate` is pure so every
verdict can be tested from a facts dictionary; `collect` gathers the facts from Windows.
Two separate answers: `can_install` (preconditions that no install step can create) and
`protection` (how much of L1 is already installed).
"""
import sys

from . import connections, l1_consent, remote_backend

from ..backend import location as backend_location
from ..errors import SafetyError
from .. import config
from .. import layout
from ..windows.system_facts import system_facts
from ..model.status import Check, ProtectionLevel, Readiness
from ..model.notes import Note
from ..model.ids import utc_now

MIN_BUILD = 22000          # Windows 11
MIN_FREE_GB = 2.0
BLOCKING_FREE_GB = 0.5
PROGRAM_FILES = (config.CONTROLLER_EXE,)

def collect(paths) -> dict:
    """All I/O. Every failure becomes None/unknown, never an exception that hides the rest."""
    try:
        facts = system_facts(desktop_family=config.DESKTOP_PACKAGE[0], owned_package=config.OWNED_PACKAGE_NAME,
                             tasks=(config.BACKEND_TASK, config.CONTROLLER_TASK), ports=config.OWN_PORTS,
                             program_folder=layout.L1_PROGRAM) or {}
    except SafetyError:
        facts = {'inspection_failed': True}
    home = paths.home
    cli = home / layout.STANDALONE_CLI
    try:
        facts['cli'] = {'present': cli.is_file(),
                        'reviewed_hash': cli.is_file()
                        and backend_location.sha256(cli) == backend_location.REVIEWED_STANDALONE_CLI}
    except OSError:
        facts['cli'] = {'present': None, 'reviewed_hash': None}
    extensions = home / layout.VSCODE_EXTENSIONS
    facts['extensions'] = sorted(p.parent.parent.parent.name.removeprefix('anthropic.claude-code-')
                                 .removesuffix('-win32-x64')
                                 for p in extensions.glob(layout.EXTENSION_CLI)
                                 if p.is_file()) if extensions.is_dir() else []
    consent = layout.controller_folder(paths.state) / l1_consent.FILE
    try:
        facts['consent'] = bool(consent.is_file() and l1_consent.load(layout.controller_folder(paths.state)))
    except (OSError, SafetyError):
        facts['consent'] = None
    try:
        facts['connection_profile'] = connections.load(paths) is not None
    except (OSError, SafetyError):
        facts['connection_profile'] = None
    try:
        facts['remote_backend'] = remote_backend.load(paths) is not None
    except (OSError, SafetyError):
        facts['remote_backend'] = None
    facts['frozen'] = bool(getattr(sys, 'frozen', False))
    facts['python'] = '.'.join(str(v) for v in sys.version_info[:3])
    return facts


def row(identifier: str, status: Check, detail: object, **extra: object) -> dict:
    return {'id': identifier, 'status': status, 'detail': detail, **extra}


# --- preconditions: each returns its row, or None when it does not apply -----------------------------------

def windows_row(facts: dict) -> dict:
    build, arch = facts.get('os_build'), facts.get('cpu_architecture')
    return row('windows', Check.OK if isinstance(build, int) and build >= MIN_BUILD and arch == 9 else Check.BLOCKED,
               Note('check.windows', caption=facts.get('os_caption') or 'Windows', build=build,
                    arch='x64' if arch == 9 else 'architecture ' + str(arch)),
               needs='Windows 11 x64')


def bfe_row(facts: dict) -> dict:
    bfe = facts.get('bfe')
    return row('base_filtering_engine', Check.OK if bfe == 'Running' else Check.BLOCKED, Note('check.bfe', state=bfe),
               needs=Note('check.needs_bfe'))


def disk_row(facts: dict) -> dict:
    free = facts.get('free_gb')
    status = (Check.UNKNOWN if free is None else Check.BLOCKED if free < BLOCKING_FREE_GB
              else Check.WARN if free < MIN_FREE_GB else Check.OK)
    return row('disk_space', status, Note('check.disk', free=free))


def desktop_row(facts: dict) -> dict | None:
    desktop = facts.get('desktop')
    if desktop:
        return row('client_desktop', Check.OK,
                   Note('check.desktop', version=desktop.get('version'), family=desktop.get('family')))
    return None


def extension_row(facts: dict) -> dict | None:
    extensions = facts.get('extensions') or []
    if extensions:
        return row('client_vscode_extension', Check.OK, Note('check.extension', versions=', '.join(extensions)))
    return None


def cli_row(facts: dict) -> dict | None:
    cli = facts.get('cli') or {}
    if cli.get('present'):
        reviewed = cli.get('reviewed_hash')
        return row('client_standalone_cli', Check.OK if reviewed else Check.WARN,
                   Note('check.cli_reviewed' if reviewed else 'check.cli_unreviewed'))
    if cli.get('present') is False:
        return row('client_standalone_cli', Check.INFO, Note('check.cli_absent'))
    return None


def clients(facts: dict) -> list[str]:
    """The Claude clients found on this PC, in a fixed order."""
    found = [('desktop', bool(facts.get('desktop'))), ('extension', bool(facts.get('extensions'))),
             ('cli', bool((facts.get('cli') or {}).get('present')))]
    return [name for name, present in found if present]


def clients_row(facts: dict) -> dict:
    found = clients(facts)
    return row('claude_client', Check.OK if found else Check.BLOCKED,
               Note('check.clients', found=', '.join(found)) if found else Note('check.no_clients'),
               needs=Note('check.needs_client'))


def proxy_row(facts: dict) -> dict:
    proxies = (['Internet Settings'] if facts.get('wininet_proxy') else []) + list(facts.get('proxy_variables') or [])
    return row('ordinary_proxy', Check.WARN if proxies else Check.OK,
               Note('check.proxies', found=', '.join(proxies)) if proxies else Note('check.no_proxies'))


def developer_mode_row(facts: dict) -> dict:
    dev = facts.get('dev_mode') or {}
    return row('developer_mode', Check.INFO,
               Note('check.developer_mode', development=dev.get('allow_development'),
                    trusted=dev.get('allow_all_trusted')))


def elevation_row(facts: dict) -> dict:
    return row('elevation', Check.INFO, Note('check.elevated' if facts.get('elevated') else 'check.not_elevated'))


def cowork_row(facts: dict) -> dict:
    return row('cowork', Check.INFO, Note('check.cowork', state=facts.get('cowork_service')))


def unsigned_row(facts: dict) -> dict | None:
    if facts.get('isolation_package'):
        return None
    unsigned = facts.get('allow_unsigned')
    return row('unsigned_package_registration',
               Check.OK if unsigned else Check.UNKNOWN if unsigned is None else Check.BLOCKED,
               Note('check.unsigned_available' if unsigned else 'check.unsigned_unavailable' if unsigned is False
                    else 'check.unsigned_unknown'),
               needs=Note('check.needs_unsigned'))


PRECONDITIONS = (windows_row, bfe_row, disk_row, desktop_row, extension_row, cli_row, clients_row, proxy_row,
                 developer_mode_row, elevation_row, cowork_row, unsigned_row)


# --- what is installed -------------------------------------------------------------------------------------------

def installed_parts(facts: dict) -> dict[str, bool]:
    tasks, listeners = facts.get('tasks') or {}, facts.get('listeners') or {}
    return {
        'isolation_package': bool(facts.get('isolation_package')),
        # A remote SOCKS5 profile needs no engine task or loopback listener: the controller's relay does the work.
        'backend_task': facts.get('remote_backend') is True or tasks.get(config.BACKEND_TASK) is not None,
        'backend_listening': facts.get('remote_backend') is True or bool(listeners.get(str(config.BACKEND_PORT))),
        'controller_files': all(name in (facts.get('program_files') or []) for name in PROGRAM_FILES),
        'controller_task': tasks.get(config.CONTROLLER_TASK) is not None,
        'connection_profile': facts.get('connection_profile') is True,
        'consent': facts.get('consent') is True,
        'relay_listening': bool(listeners.get(str(config.RELAY_PORT))),
    }


def protection_level(parts: dict[str, bool]) -> ProtectionLevel:
    if all(parts.values()):
        return ProtectionLevel.INSTALLED
    if not any(parts[k] for k in ('isolation_package', 'backend_task', 'controller_files', 'controller_task', 'consent',
                                  'connection_profile')):
        return ProtectionLevel.NOT_INSTALLED
    return ProtectionLevel.PARTIAL


def next_steps(blockers: list[dict], protection: ProtectionLevel) -> list[Note]:
    if blockers:
        return [Note('check.fix', id=b['id'], needs=b.get('needs') or b['detail']) for b in blockers]
    if protection != ProtectionLevel.INSTALLED:
        return [Note('check.ready')]
    return []


def evaluate(facts: dict) -> dict:
    """status: ok | info | warn | missing (an install step creates it) | blocked (no install step can fix it)
    | unknown."""
    if facts.get('inspection_failed'):
        rows = [row('windows_inspection', Check.UNKNOWN, Note('check.no_answer'))]
        return {'schema': 1, 'utc': utc_now(), 'status': Readiness.UNKNOWN,
                'can_install': None,
                'protection': ProtectionLevel.UNKNOWN, 'checks': rows, 'blockers': [],
                'next_steps': [Note('check.retry')],
                'changes_system': False, 'network_requests': 0}
    rows = [found for check in PRECONDITIONS if (found := check(facts)) is not None]
    blockers = [r for r in rows if r['status'] == Check.BLOCKED]
    parts = installed_parts(facts)
    rows += [row(name, Check.OK if present else Check.MISSING,
                 Note('check.installed' if present else 'check.not_installed'))
             for name, present in parts.items()]
    protection = protection_level(parts)
    status = (Readiness.BLOCKED if blockers else Readiness(protection) if protection != ProtectionLevel.NOT_INSTALLED
              else Readiness.READY_TO_INSTALL)
    cli = facts.get('cli') or {}
    return {'schema': 1, 'utc': utc_now(), 'status': status, 'can_install': not blockers,
            'protection': protection, 'checks': rows, 'blockers': [b['id'] for b in blockers],
            'next_steps': next_steps(blockers, protection),
            'client_versions': {'desktop': (facts.get('desktop') or {}).get('version'),
                                'vscode_extensions': facts.get('extensions') or [],
                                'standalone_cli_present': cli.get('present')},
            'environment': {'python': facts.get('python'), 'frozen': facts.get('frozen')},
            'changes_system': False, 'network_requests': 0}


def check(paths) -> dict:
    report = evaluate(collect(paths))
    # Exit code 0 means "can be installed or already is"; blockers make the CLI exit 2.
    report['passed'] = report['can_install'] is True
    return report
