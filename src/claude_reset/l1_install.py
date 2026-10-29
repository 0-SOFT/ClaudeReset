"""One command that takes a PC from "backend installed" to "L1 protection running", step by step.

Order (each step stops the run on failure and nothing later is attempted):
  check -> extension decision -> package (UAC) -> consent -> build on this PC -> autostart (UAC) -> start -> verify
The consent comes after the package because listing the open boundaries runs the DNS probe inside it. Every step is
idempotent, so a run that stops at the consent can simply be repeated with --confirm-l1-limits.
The first outage for protected clients is the start step; everything before it only prepares files.
Claude Code in the shared VS Code is NOT protected unless --protect-vscode-extension is given: protecting it
cuts a running session (including the one that runs this command) until its proxy setting is applied and the
window is reloaded, which is how the relay outage of 27 October happened.
Requires the backend (--l1-backend-install) and a recorded exit profile. The elevated controller must live in an
administrator-only folder: an installed copy ships it prebuilt in controller/ (verified by manifest), a source
checkout builds it here with PyInstaller.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

from . import l1_check, package_isolation, strict_guard
from .safeio import SafetyError
from .uac_request import serialized, blocked

ROOT = Path(__file__).resolve().parents[2]
EXCLUDE_FLAG = 'exclude-vscode-extension.flag'
BUILDS = (('ClaudeReset', 'src/launcher.py', '--windowed'), ('ClaudeResetRun', 'src/launcher_run.py', '--console'))
NO_WINDOW = 0x08000000


KIT = ROOT / 'controller'  # prebuilt by tools/build_bundle.py in an installed copy; absent in a source checkout
SOURCE_FILES = ('src/launcher.py', 'src/launcher_run.py')


def source_digest(root=ROOT):
    """SHA-256 over the controller's sources, so a prebuilt kit is used only with the code it was built from."""
    import hashlib
    digest = hashlib.sha256()
    files = sorted({root / name for name in SOURCE_FILES} | set((root / 'src/claude_reset').rglob('*.py')))
    for file in files:
        digest.update(file.relative_to(root).as_posix().encode() + b'\0' + file.read_bytes() + b'\0')
    return digest.hexdigest()


def controller_kit(*, kit=None, root=ROOT):
    """The prebuilt controller next to the program, verified against its manifest; None when there is none.

    A kit built from other sources (an update without a new kit) is not used: the caller builds instead."""
    import hashlib
    kit = kit or root / 'controller'
    manifest = kit / 'manifest.json'
    if not manifest.is_file():
        return None
    try:
        data = json.loads(manifest.read_text('utf-8'))
    except ValueError:
        raise SafetyError('Манифест готового контроллера повреждён') from None
    if data.get('schema') != 1 or data.get('source_sha256') != source_digest(root):
        return None
    for name, _, _ in BUILDS:
        file = kit / (name + '.exe')
        if not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest() != (data.get('files') or {}).get(file.name):
            raise SafetyError('Готовый контроллер повреждён или изменён; переустановите программу')
    return kit


def prepare_executables(out):
    """The release's prebuilt controller when present and matching, otherwise a PyInstaller build on this PC."""
    return controller_kit() or build_executables(out)


def build_executables(out):
    """PyInstaller on this PC. Returns the dist folder holding ClaudeReset.exe and ClaudeResetRun.exe."""
    out.mkdir(parents=True, exist_ok=True)
    for name, entry, mode in BUILDS:
        result = subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--noupx', mode,
                                 '--name', name, '--paths', str(ROOT / 'src'), '--distpath', str(out / 'dist'),
                                 '--workpath', str(out / ('build-' + name)), '--specpath', str(out / 'spec'), str(ROOT / entry)],
                                capture_output=True, text=True, timeout=600, creationflags=NO_WINDOW)
        if result.returncode:
            raise SafetyError(f'Build of {name} failed; is PyInstaller installed (pip install -r requirements-dev.txt)?')
    dist = out / 'dist'
    for name, _, _ in BUILDS:
        if not (dist / (name + '.exe')).is_file():
            raise SafetyError(name + '.exe was not produced')
    return dist


def run_autostart(exe, paths, *, wait_seconds=300, sleep=time.sleep, clock=time.monotonic):
    """Elevate the built program with a durable claim and await only its receipt.

    ShellExecute may wait for the owner to answer UAC. No process timeout kills
    that interaction; the receipt deadline starts only after dispatch returns.
    Unknown and partial outcomes retain the shared claim and forbid replay.
    """
    from .uac_request import execute
    return execute(paths, 'autostart',
                   lambda request: strict_guard.dispatch_request(request, executable=exe),
                   wait_seconds=wait_seconds, sleep=sleep, clock=clock)


def read_status(folder):
    try:
        data = json.loads((folder / 'status.json').read_text('utf-8'))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def current_instance(folder):
    """Instance id of the controller that last wrote the status file (None when there is none)."""
    instance = read_status(folder).get('instance')
    return instance if isinstance(instance, str) else None


def task_state():
    from . import backend_install, netguard
    code, out, _ = backend_install.powershell(
        f"$ErrorActionPreference='Stop'; try {{ $t=@(Get-ScheduledTask -ErrorAction Stop | "
        f"Where-Object {{ $_.TaskName -eq {netguard.psq(l1_check.CONTROLLER_TASK)} }}); "
        "if ($t.Count -eq 0) { 'Missing' } elseif ($t.Count -eq 1) { [string]$t[0].State } "
        "else { exit 1 }; exit 0 } catch { exit 1 }")
    return out.strip() if code == 0 else None


def wait_task_idle(seconds=90, *, state=task_state, sleep=time.sleep, clock=time.monotonic):
    """The task ignores a run request while its previous process tree is still alive (MultipleInstancesPolicy
    IgnoreNew), and a closed relay port does not mean that process has exited. Wait until it is idle."""
    deadline = clock() + seconds
    while clock() < deadline:
        if state() in ('Ready', 'Disabled', 'Missing'):
            return True
        sleep(1)
    return False


def start_controller(folder=None, stale=None, *, attempts=3, wait_each=45, run=subprocess.run, sleep=time.sleep, clock=time.monotonic):
    """Authorize one scheduler start and observe that exact request on a new instance.

    `stale` is the instance id of the controller that was just stopped: its last status file must not count.
    True means only that an exact status was observed; ownership remains
    uncertain and callers must stop mutations until domain reconciliation.
    """
    from .controller_admission import schedule
    request = schedule(folder)
    from types import SimpleNamespace
    from .uac_request import _chain, _event
    owner = _chain.get()
    paths = SimpleNamespace(local=owner.pending.parent.parent, state=Path(request.state_root))
    try:
        _event(paths, request, 'dispatch')
        for attempt in range(1, attempts + 1):
            # Persist each invocation before schtasks; a torn/missing outcome
            # remains uncertain even if a later invocation is observed.
            prefix = 'scheduler-' + str(attempt)
            _event(paths, request, prefix + '-dispatch')
            try:
                result = run(['schtasks', '/Run', '/TN', l1_check.CONTROLLER_TASK], capture_output=True, text=True,
                             timeout=60, creationflags=NO_WINDOW)
            except BaseException:
                _event(paths, request, prefix + '-error')
                raise
            _event(paths, request, prefix + ('-accepted' if result.returncode == 0 else '-nonzero'))
            if result.returncode != 0:
                sleep(5)
                continue
            deadline = clock() + wait_each
            while clock() < deadline:
                state = read_status(folder)
                fresh = state.get('instance')
                if (fresh is not None and fresh != stale
                        and state.get('request_id') == request.request_id
                        and state.get('state_root') == request.state_root
                        and state.get('operation') == 'start'):
                    _event(paths, request, 'receipt-observed')
                    _event(paths, request, prefix + '-observed')
                    return True
                sleep(1)
            _event(paths, request, prefix + '-unobserved')
        return False
    finally:
        # Even an exact status is only a historical observation. Scheduler
        # completion and relay readiness do not establish current resources,
        # process-tree completeness or an exclusive controller handoff.
        owner.uncertain = True


def wait_for_relay(folder, stale=None, *, seconds=150, sleep=time.sleep, clock=time.monotonic):
    """Wait for relay_open from a controller other than `stale`. The stopped controller's own last status
    ('blocked_controller_stopped') is old news and is neither success nor failure of the new one."""
    from . import l1_mechanism
    from .uac_request import _chain
    owner = _chain.get()
    expected = owner.start_request if owner is not None else None
    deadline = clock() + seconds
    state = {}
    while clock() < deadline:
        state = read_status(folder)
        if expected is not None and any(state.get(key) != getattr(expected, key)
                                        for key in ('request_id', 'operation', 'state_root')):
            state = {}
        if stale is not None and state.get('instance') == stale:
            state = {}
        if state.get('state') == 'relay_open' and l1_mechanism.connect('127.0.0.1', strict_guard.GATE_PORT, .5) == 'connected':
            return True, state
        if str(state.get('state', '')).startswith(('blocked', 'installation_failed')):
            return False, state
        sleep(2)
    return False, state


def set_extension_proxy():
    result = subprocess.run([sys.executable, str(ROOT / 'tools/vscode_claude_proxy.py'), 'set'], capture_output=True, text=True,
                            timeout=60, creationflags=NO_WINDOW)
    return result.returncode == 0


class Deps:
    check = staticmethod(l1_check.check)
    current_instance = staticmethod(current_instance)
    build = staticmethod(prepare_executables)
    autostart = staticmethod(run_autostart)
    start = staticmethod(start_controller)
    wait_relay = staticmethod(wait_for_relay)
    extension_proxy = staticmethod(set_extension_proxy)

    @staticmethod
    def exclude_extension(paths):
        from .extension_protection import exclude
        return exclude(paths)

    @staticmethod
    def stop_controller(paths):
        from .l1_remove import wait_relay_gone
        receipt = strict_guard.request_close(paths)
        if receipt.get('status') != 'strict_close_requested' or receipt.get('retry_blocked'):
            return False
        return wait_relay_gone() and wait_task_idle()

    @staticmethod
    def register_package(paths):
        return package_isolation.dispatch(paths, '--l1-package-register-serve', 'package-register-')

    @staticmethod
    def consent(paths, confirmed):
        return strict_guard.l1_accept(paths, confirmed)


@serialized('l1_restart', completed={'restarted', 'not_installed', 'proxy_confirmation_required'})
def restart(paths, *, deps=None, clock=time.monotonic, proxy_draft=None, protect_extension=None):
    """Restart without reinstalling; excluding extension filters requires UAC.

    Protected clients have no network between the stop and the new relay_open; the report says for how long.
    Starting is retried for several minutes because leaving the relay closed is the worse outcome."""
    d = deps or Deps()
    report = {'schema': 1, 'action': 'l1_restart', 'finished': False}
    folder = strict_guard.directory(paths)
    began = clock()
    try:
        previous = d.current_instance(folder)
        state = d.check(paths)
        checks = {c['id']: c['status'] for c in state.get('checks', [])}
        if checks.get('controller_task') != 'ok' or checks.get('controller_files') != 'ok':
            report.update(status='not_installed', finished=True)
            return report
        if proxy_draft is not None and proxy_draft.expected is None:
            return dict(report, status='proxy_confirmation_required', finished=True)
        if not d.stop_controller(paths):
            report.update(status='controller_not_stopped', finished=True)
            return report
        stopped = clock()
        if proxy_draft is not None:
            proxy_draft.save(paths, confirmed=True)
            report['profile_saved'] = True
        if protect_extension is False:
            receipt = d.exclude_extension(paths)
            if receipt.get('passed') is not True:
                return dict(report, status='extension_exclusion_failed', finished=True,
                            retry_blocked=receipt.get('retry_blocked') is True)
            folder.mkdir(parents=True, exist_ok=True)
            (folder / EXCLUDE_FLAG).write_text('Excluded by explicit owner choice\n')
            report['extension_protection'] = 'excluded'
        if protect_extension is True:
            (folder / EXCLUDE_FLAG).unlink(missing_ok=True)
            if not d.extension_proxy():
                return dict(report, status='extension_proxy_failed', finished=True)
        started = d.start(folder, previous, attempts=8)
        if blocked(paths):
            report.update(status='reconcile_required', retry_blocked=True,
                          requires_live_verification=True, finished=True)
            return report
        if not started:
            report.update(status='start_failed', clients_without_network=True, finished=True,
                          next='schtasks /Run /TN "ClaudeReset L1 Controller"; затем --l1-check')
            return report
        up, status = d.wait_relay(folder, previous)
        report.update(status='restarted' if up else 'relay_not_open', controller_state=status.get('state'), level=status.get('level'),
                      seconds_without_relay=round(clock() - stopped, 1), seconds_total=round(clock() - began, 1), finished=True)
        if not up:
            report.update(clients_without_network=True, reason=status.get('stop_reason') or status.get('error_reason'))
    except BaseException as exc:
        report.update(status='failed', error=type(exc).__name__ + ': ' + str(exc)[:200], finished=True)
    return report


@serialized('l1_install', completed={'installed', 'blocked', 'needs_backend', 'needs_connection_profile'})
def run(paths, *, confirmed=False, protect_extension=None, reinstall_controller=False, deps=None, build_dir=None):
    d = deps or Deps()
    report = {'schema': 1, 'action': 'l1_install', 'finished': False, 'steps': []}

    def stop(status, step, **extra):
        report['steps'].append({'step': step, 'status': 'stopped', **extra})
        report.update(status=status, finished=True)
        return report

    def ok(step, **extra):
        report['steps'].append({'step': step, 'status': 'ok', **extra})
    folder = strict_guard.directory(paths)
    try:
        state = d.check(paths)
        if not state.get('can_install'):
            return stop('blocked', 'check', blockers=state.get('blockers'))
        checks = {c['id']: c['status'] for c in state['checks']}
        if checks.get('backend_task') != 'ok' or checks.get('backend_listening') != 'ok':
            return stop('needs_backend', 'check', next='Установите backend: --l1-backend-install PROFILE')
        if checks.get('connection_profile') != 'ok':
            return stop('needs_connection_profile', 'check', next='Сохраните ожидаемый выход: --connection-save FILE (шаблон examples/connection.example.json)')
        ok('check', protection=state.get('protection'))
        installed = checks.get('controller_task') == 'ok' and checks.get('controller_files') == 'ok'
        replacing = not installed or reinstall_controller
        previous = d.current_instance(folder)
        if replacing and (checks.get('controller_task') == 'ok' or
                          checks.get('controller_files') == 'ok' or
                          checks.get('relay_listening') == 'ok'):
            # A closed port is not proof of exit. Stop before changing the
            # extension decision, package, consent or installed executable files.
            if not d.stop_controller(paths):
                return stop('controller_not_stopped', 'restart', next='Проверьте status.json контроллера')
            ok('controller_stopped_for_restart')
        folder.mkdir(parents=True, exist_ok=True)
        flag = folder / EXCLUDE_FLAG
        if protect_extension is None:
            # No explicit choice. A fresh install leaves the editor out (see the module note); an installed controller
            # keeps what it has: writing the flag there would drop the extension's relay permit while its deny stays.
            protect_extension = (not flag.exists()) if installed else False
        if protect_extension:
            flag.unlink(missing_ok=True)
        else:
            flag.write_text('Claude Code in the shared VS Code is not protected until --l1-install --protect-vscode-extension\n')
        report['extension_protection'] = 'protected' if protect_extension else 'excluded'
        ok('extension_decision', mode=report['extension_protection'])
        if checks.get('isolation_package') != 'ok':
            registered = d.register_package(paths)
            if registered.get('passed') is not True:
                return stop('package_failed', 'package', detail=registered.get('status'), error=registered.get('error'))
        ok('package')
        if checks.get('consent') != 'ok':
            listed = d.consent(paths, confirmed)
            if listed.get('passed') is not True:
                return stop('needs_consent', 'consent', open_boundaries=listed.get('open_boundaries'),
                            next='Прочитайте список и повторите с --confirm-l1-limits')
        ok('consent')
        if installed and not reinstall_controller:
            # Resuming after a stopped run: the controller is already in Program Files, so no build and no UAC.
            ok('controller_reused', note='Установленный контроллер сохранён; для замены используйте --reinstall-controller')
        else:
            dist = d.build(build_dir or (Path.home() / '.claude-reset' / 'build'))
            ok('build', folder=str(dist))
            receipt = d.autostart(dist / 'ClaudeReset.exe', paths)
            if receipt.get('passed') is not True:
                return stop('autostart_failed', 'autostart', detail=receipt.get('status'),
                            retry_blocked=receipt.get('retry_blocked') is True)
            ok('autostart')
        if checks.get('relay_listening') == 'ok' and installed and not reinstall_controller:
            up, status = True, {'state': 'relay_open', 'note': 'controller already running'}
        else:
            started = d.start(folder, previous)
            if blocked(paths):
                return stop('reconcile_required', 'start', retry_blocked=True,
                            requires_live_verification=True)
            if not started:
                return stop('start_failed', 'start', clients_without_network=True,
                            next='Запустите вручную: schtasks /Run /TN "ClaudeReset L1 Controller"; затем повторите --l1-install')
            up, status = d.wait_relay(folder, previous)
        if not up:
            return stop('relay_not_open', 'start', controller_state=status.get('state'), reason=status.get('stop_reason') or status.get('error_reason'),
                        clients_without_network=True, next='schtasks /Run /TN "ClaudeReset L1 Controller"; затем --l1-check')
        ok('start', controller_state=status.get('state'), level=status.get('level'))
        if protect_extension and not d.extension_proxy():
            return stop('extension_proxy_failed', 'extension', next='tools/vscode_claude_proxy.py set; затем Developer: Reload Window')
        final = d.check(paths)
        ok('verify', protection=final.get('protection'))
        report.update(status='installed' if final.get('protection') == 'installed' else 'installed_needs_attention', finished=True)
    except BaseException as exc:
        report.update(status='failed', error=type(exc).__name__ + ': ' + str(exc)[:200], finished=True)
    return report
