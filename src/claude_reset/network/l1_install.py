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
import sys
import time
from pathlib import Path

from .. import config, layout
from ..elevation import launch
from ..elevation.claims import blocked, serialized
from ..errors import SafetyError, error_info
from ..model.report import OperationReport
from ..model.status import Check, Network, NextAction, Protection, ProtectionLevel
from ..windows import process, tasks, tcp
from ..windows.powershell import run_process
from . import controller, controller_status, l1_check, l1_consent, package_isolation
from .controller_status import current_instance
from .l1_common import wait_relay_gone, wait_task_idle

__all__ = ['BUILDS', 'Deps', 'build_executables', 'controller_kit', 'prepare_executables', 'restart', 'run',
           'run_autostart', 'source_digest', 'start_controller', 'wait_for_relay']

ROOT = layout.PROGRAM_DIR
BUILDS = ((Path(config.CONTROLLER_EXE).stem, 'src/launcher.py', '--windowed'), (Path(config.RUNNER_EXE).stem, 'src/launcher_run.py', '--console'))


SOURCE_FILES = ('src/launcher.py', 'src/launcher_run.py')


def source_digest(root=ROOT):
    """SHA-256 over the controller's sources, so a prebuilt kit is used only with the code it was built from."""
    import hashlib
    digest = hashlib.sha256()
    files = sorted({root / name for name in SOURCE_FILES} | set((root / 'src/claude_reset').rglob('*.py')))
    for file in files:
        digest.update(file.relative_to(root).as_posix().encode() + b'\0' + file.read_bytes() + b'\0')
    return digest.hexdigest()


def controller_kit(*, kit=None, root=ROOT):   # None: the controller folder of root
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
        raise SafetyError('The manifest of the prebuilt controller is damaged', code='controller_manifest_damaged') from None
    if data.get('schema') != 1 or data.get('source_sha256') != source_digest(root):
        return None
    for name, _, _ in BUILDS:
        file = kit / (name + '.exe')
        if not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest() != (data.get('files') or {}).get(file.name):
            raise SafetyError('The prebuilt controller is damaged or changed; reinstall the program', code='controller_damaged')
    return kit


def build_executables(out):
    """PyInstaller on this PC. Returns the dist folder holding ClaudeReset.exe and ClaudeResetRun.exe."""
    out.mkdir(parents=True, exist_ok=True)
    for name, entry, mode in BUILDS:
        result = process.run_quietly([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--noupx',
                                      mode, '--name', name, '--paths', str(ROOT / 'src'), '--distpath', str(out / 'dist'),
                                      '--workpath', str(out / ('build-' + name)), '--specpath', str(out / 'spec'),
                                      str(ROOT / entry)], timeout=600)
        if result.returncode:
            raise SafetyError(f'Build of {name} failed; is PyInstaller installed (pip install -r requirements-lock.txt)?')
    dist = out / 'dist'
    for name, _, _ in BUILDS:
        if not (dist / (name + '.exe')).is_file():
            raise SafetyError(name + '.exe was not produced')
    return dist


def prepare_executables(out, *, kit=controller_kit, build=build_executables):
    """The release's prebuilt controller when present and matching, otherwise a PyInstaller build on this PC.
    kit finds the prebuilt controller and build runs PyInstaller."""
    return kit() or build(out)


def run_autostart(exe, paths, *, wait_seconds=300, sleep=time.sleep, clock=time.monotonic,
                  dispatch=launch.dispatch_request):
    """Elevate the built program with a durable claim and await only its receipt.

    ShellExecute may wait for the owner to answer UAC. No process timeout kills
    that interaction; the receipt deadline starts only after dispatch returns.
    Unknown and partial outcomes retain the shared claim and forbid replay.
    dispatch shows the UAC prompt.
    """
    from ..elevation.request import execute
    return execute(paths, 'autostart',
                   lambda request: dispatch(request, executable=exe),
                   wait_seconds=wait_seconds, sleep=sleep, clock=clock)


def start_controller(folder=None, stale=None, *, attempts=3, wait_each=45, run=run_process, sleep=time.sleep,
                     clock=time.monotonic):
    """Authorize one scheduler start and observe that exact request on a new instance.

    `stale` is the instance id of the controller that was just stopped: its last status file must not count.
    True means only that an exact status was observed; ownership remains
    uncertain and callers must stop mutations until domain reconciliation.
    """
    from ..elevation.request import schedule
    request = schedule(folder)
    from types import SimpleNamespace

    from ..elevation.claims import chain
    from ..elevation.request import record_event
    owner = chain.get()
    paths = SimpleNamespace(local=owner.pending.parent.parent, state=Path(request.state_root))
    try:
        record_event(paths, request, 'dispatch')
        for attempt in range(1, attempts + 1):
            # Persist each invocation before schtasks; a torn/missing outcome
            # remains uncertain even if a later invocation is observed.
            prefix = 'scheduler-' + str(attempt)
            record_event(paths, request, prefix + '-dispatch')
            try:
                result = tasks.run_now(config.CONTROLLER_TASK, run)
            except BaseException:
                record_event(paths, request, prefix + '-error')
                raise
            record_event(paths, request, prefix + ('-accepted' if result.returncode == 0 else '-nonzero'))
            if result.returncode != 0:
                sleep(5)
                continue
            deadline = clock() + wait_each
            while clock() < deadline:
                state = controller_status.read_or_empty(folder)
                fresh = state.get('instance')
                if (fresh is not None and fresh != stale
                        and state.get('request_id') == request.request_id
                        and state.get('state_root') == request.state_root
                        and state.get('operation') == 'start'):
                    record_event(paths, request, 'receipt-observed')
                    record_event(paths, request, prefix + '-observed')
                    return True
                sleep(1)
            record_event(paths, request, prefix + '-unobserved')
        return False
    finally:
        # Even an exact status is only a historical observation. Scheduler
        # completion and relay readiness do not establish current resources,
        # process-tree completeness or an exclusive controller handoff.
        owner.uncertain = True


def wait_for_relay(folder, stale=None, *, seconds=150, sleep=time.sleep, clock=time.monotonic, connect=tcp.connect):
    """Wait for relay_open from a controller other than `stale`. The stopped controller's own last status
    ('blocked_controller_stopped') is old news and is neither success nor failure of the new one.
    connect probes the relay port."""
    from ..elevation.claims import chain
    owner = chain.get()
    expected = owner.start_request if owner is not None else None
    deadline = clock() + seconds
    state = {}
    while clock() < deadline:
        state = controller_status.read_or_empty(folder)
        if expected is not None and any(state.get(key) != getattr(expected, key)
                                        for key in ('request_id', 'operation', 'state_root')):
            state = {}
        if stale is not None and state.get('instance') == stale:
            state = {}
        if state.get('state') == 'relay_open' and connect(config.LOOPBACK, config.RELAY_PORT, .5) == 'connected':
            return True, state
        if str(state.get('state', '')).startswith(('blocked', 'installation_failed')):
            return False, state
        sleep(2)
    return False, state


def set_extension_proxy():
    result = process.run_quietly([sys.executable, str(ROOT / 'tools/vscode_claude_proxy.py'), 'set'], timeout=60)
    return result.returncode == 0


class Deps:
    """The steps of an L1 install and restart: the port that tests replace with scripted steps."""
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
        receipt = controller.request_close(paths)
        if receipt.get('status') != Network.STRICT_CLOSE_REQUESTED or receipt.get('retry_blocked'):
            return False
        return wait_relay_gone() and wait_task_idle()

    @staticmethod
    def register_package(paths):
        return package_isolation.dispatch(paths, '--l1-package-register-serve', 'package-register-')

    @staticmethod
    def consent(paths, confirmed):
        return l1_consent.accept(paths, confirmed)


@serialized('l1_restart', completed={Protection.RESTARTED, Protection.NOT_INSTALLED, Protection.PROXY_CONFIRMATION_REQUIRED})
def restart(paths, *, deps=Deps(), clock=time.monotonic, proxy_draft=None, protect_extension=None):
    """Restart without reinstalling; excluding extension filters requires UAC.

    Protected clients have no network between the stop and the new relay_open; the report says for how long.
    Starting is retried for several minutes because leaving the relay closed is the worse outcome."""
    report = {'schema': 1, 'action': 'l1_restart', 'finished': False}
    folder = layout.controller(paths)
    began = clock()
    try:
        previous = deps.current_instance(folder)
        state = deps.check(paths)
        checks = {c['id']: c['status'] for c in state.get('checks', [])}
        if checks.get('controller_task') != Check.OK or checks.get('controller_files') != Check.OK:
            report.update(status=Protection.NOT_INSTALLED, finished=True)
            return report
        if proxy_draft is not None and proxy_draft.expected is None:
            return dict(report, status=Protection.PROXY_CONFIRMATION_REQUIRED, finished=True)
        if not deps.stop_controller(paths):
            report.update(status=Protection.CONTROLLER_NOT_STOPPED, finished=True)
            return report
        stopped = clock()
        if proxy_draft is not None:
            proxy_draft.save(paths, confirmed=True)
            report['profile_saved'] = True
        if protect_extension is False:
            receipt = deps.exclude_extension(paths)
            if receipt.get('passed') is not True:
                return dict(report, status=Protection.EXTENSION_EXCLUSION_FAILED, finished=True,
                            retry_blocked=receipt.get('retry_blocked') is True)
            folder.mkdir(parents=True, exist_ok=True)
            (folder / layout.EXTENSION_EXCLUDED_FLAG).write_text('Excluded by explicit owner choice\n')
            report['extension_protection'] = 'excluded'
        if protect_extension is True:
            (folder / layout.EXTENSION_EXCLUDED_FLAG).unlink(missing_ok=True)
            if not deps.extension_proxy():
                return dict(report, status=Protection.EXTENSION_PROXY_FAILED, finished=True)
        started = deps.start(folder, previous, attempts=8)
        if blocked(paths):
            report.update(status=Protection.RECONCILE_REQUIRED, retry_blocked=True,
                          requires_live_verification=True, finished=True)
            return report
        if not started:
            report.update(status=Protection.START_FAILED, clients_without_network=True, finished=True,
                          next=NextAction.START_CONTROLLER_THEN_CHECK)
            return report
        up, status = deps.wait_relay(folder, previous)
        report.update(status=Protection.RESTARTED if up else Protection.RELAY_NOT_OPEN, controller_state=status.get('state'), level=status.get('level'),
                      seconds_without_relay=round(clock() - stopped, 1), seconds_total=round(clock() - began, 1), finished=True)
        if not up:
            report.update(clients_without_network=True, reason=status.get('stop_reason') or status.get('error_reason'))
    except Exception as exc:
        report.update(status=Protection.FAILED, error=error_info(exc), finished=True)
    return report


class Install:
    """One L1 install, step by step. Each step reports itself; a step that stops the install returns False."""

    def __init__(self, paths: layout.Paths, deps: Deps, report: OperationReport, folder: Path, *, confirmed: bool,
                 protect_extension: bool | None, reinstall_controller: bool, build_dir: Path | None) -> None:
        self.paths, self.d, self.report, self.folder = paths, deps, report, folder
        self.confirmed, self.protect_extension = confirmed, protect_extension
        self.reinstall_controller, self.build_dir = reinstall_controller, build_dir
        self.checks, self.installed, self.previous = {}, False, None
        self.up, self.status = False, {}

    def check(self) -> bool:
        state = self.d.check(self.paths)
        if not state.get('can_install'):
            self.report.stop(Protection.BLOCKED, 'check', blockers=state.get('blockers'))
            return False
        checks = self.checks = {c['id']: c['status'] for c in state['checks']}
        if checks.get('backend_task') != Check.OK or checks.get('backend_listening') != Check.OK:
            self.report.stop(Protection.NEEDS_BACKEND, 'check', next=NextAction.INSTALL_BACKEND)
            return False
        if checks.get('connection_profile') != Check.OK:
            self.report.stop(Protection.NEEDS_CONNECTION_PROFILE, 'check', next=NextAction.SAVE_CONNECTION_PROFILE)
            return False
        self.report.ok('check', protection=state.get('protection'))
        self.installed = checks.get('controller_task') == Check.OK and checks.get('controller_files') == Check.OK
        return True

    @property
    def reusing(self) -> bool:
        """The controller is already in Program Files and is kept: no build and no UAC."""
        return self.installed and not self.reinstall_controller

    def stop_running_controller(self) -> bool:
        checks = self.checks
        self.previous = self.d.current_instance(self.folder)
        if not self.reusing and (checks.get('controller_task') == Check.OK or checks.get('controller_files') == Check.OK
                                 or checks.get('relay_listening') == Check.OK):
            # A closed port is not proof of exit. Stop before changing the
            # extension decision, package, consent or installed executable files.
            if not self.d.stop_controller(self.paths):
                self.report.stop(Protection.CONTROLLER_NOT_STOPPED, 'restart', next=NextAction.CHECK_CONTROLLER_STATUS)
                return False
            self.report.ok('controller_stopped_for_restart')
        return True

    def extension_decision(self) -> bool:
        self.folder.mkdir(parents=True, exist_ok=True)
        flag = self.folder / layout.EXTENSION_EXCLUDED_FLAG
        if self.protect_extension is None:
            # No explicit choice. A fresh install leaves the editor out (see the module note); an installed controller
            # keeps what it has: writing the flag there would drop the extension's relay permit while its deny stays.
            self.protect_extension = (not flag.exists()) if self.installed else False
        if self.protect_extension:
            flag.unlink(missing_ok=True)
        else:
            flag.write_text('Claude Code in the shared VS Code is not protected until --l1-install --protect-vscode-extension\n')
        self.report['extension_protection'] = 'protected' if self.protect_extension else 'excluded'
        self.report.ok('extension_decision', mode=self.report['extension_protection'])
        return True

    def ensure(self, part: str, step: str, action, status: Protection, details) -> bool:
        """Run action when part is not installed yet; stop with status and details(result) when it does not pass."""
        if self.checks.get(part) != Check.OK:
            result = action()
            if result.get('passed') is not True:
                self.report.stop(status, step, **details(result))
                return False
        self.report.ok(step)
        return True

    def package(self) -> bool:
        return self.ensure('isolation_package', 'package', lambda: self.d.register_package(self.paths), Protection.PACKAGE_FAILED,
                           lambda result: {'detail': result.get('status'), 'error': result.get('error')})

    def consent(self) -> bool:
        return self.ensure('consent', 'consent', lambda: self.d.consent(self.paths, self.confirmed), Protection.NEEDS_CONSENT,
                           lambda result: {'open_boundaries': result.get('open_boundaries'), 'next': NextAction.CONFIRM_LIMITS})

    def controller(self) -> bool:
        if self.reusing:
            # Resuming after a stopped run: the controller is already in Program Files, so no build and no UAC.
            self.report.ok('controller_reused', note=NextAction.REINSTALL_CONTROLLER_TO_REPLACE)
            return True
        dist = self.d.build(self.build_dir or (layout.tool_home(self.paths) / 'build'))
        self.report.ok('build', folder=str(dist))
        receipt = self.d.autostart(dist / config.CONTROLLER_EXE, self.paths)
        if receipt.get('passed') is not True:
            self.report.stop(Protection.AUTOSTART_FAILED, 'autostart', detail=receipt.get('status'),
                             retry_blocked=receipt.get('retry_blocked') is True)
            return False
        self.report.ok('autostart')
        return True

    def start(self) -> bool:
        if self.checks.get('relay_listening') == Check.OK and self.reusing:
            self.up, self.status = True, {'state': 'relay_open', 'note': 'controller already running'}
        else:
            started = self.d.start(self.folder, self.previous)
            if blocked(self.paths):
                self.report.stop(Protection.RECONCILE_REQUIRED, 'start', retry_blocked=True, requires_live_verification=True)
                return False
            if not started:
                self.report.stop(Protection.START_FAILED, 'start', clients_without_network=True,
                                 next=NextAction.START_CONTROLLER_THEN_INSTALL)
                return False
            self.up, self.status = self.d.wait_relay(self.folder, self.previous)
        status = self.status
        if not self.up:
            self.report.stop(Protection.RELAY_NOT_OPEN, 'start', controller_state=status.get('state'),
                             reason=status.get('stop_reason') or status.get('error_reason'),
                             clients_without_network=True, next=NextAction.START_CONTROLLER_THEN_CHECK)
            return False
        self.report.ok('start', controller_state=status.get('state'), level=status.get('level'))
        return True

    def extension(self) -> bool:
        if self.protect_extension and not self.d.extension_proxy():
            self.report.stop(Protection.EXTENSION_PROXY_FAILED, 'extension', next=NextAction.SET_EXTENSION_PROXY)
            return False
        return True

    def verify(self) -> bool:
        final = self.d.check(self.paths)
        self.report.ok('verify', protection=final.get('protection'))
        self.report.update(status=Protection.INSTALLED if final.get('protection') == ProtectionLevel.INSTALLED
                           else Protection.INSTALLED_NEEDS_ATTENTION, finished=True)
        return True

    STEPS = (check, stop_running_controller, extension_decision, package, consent, controller, start, extension, verify)

    def run(self) -> OperationReport:
        for step in self.STEPS:
            if not step(self):
                break
        return self.report


@serialized('l1_install', completed={Protection.INSTALLED, Protection.BLOCKED, Protection.NEEDS_BACKEND, Protection.NEEDS_CONNECTION_PROFILE})
def run(paths, *, confirmed=False, protect_extension=None, reinstall_controller=False, deps=Deps(), build_dir=None):
    report = OperationReport('l1_install')
    folder = layout.controller(paths)
    try:
        Install(paths, deps, report, folder, confirmed=confirmed, protect_extension=protect_extension,
                reinstall_controller=reinstall_controller, build_dir=build_dir).run()
    except Exception as exc:
        report.update(status=Protection.FAILED, error=error_info(exc), finished=True)
    return report
