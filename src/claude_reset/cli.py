"""The command line: every mode the program runs without a window, and opening the windows."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys
from . import __version__
from .layout import Paths
from .reset.planner import build_plan
from .reset.execution import Executor, recover_memory, verify_run
from .errors import SafetyError
from .safeio import atomic_json
from .ui.text import error_text, gui_message, render
from .model.reset import Selection
from .reset.policy import policy_plan
from .reset.verification import template_for_run, save_evidence
from . import config
from . import layout
from .model.status import Backend, Export, NextAction, Protection, Reset
from collections.abc import Callable
from types import MappingProxyType


# The words of the next step on the command line; the operations only name the step.
NEXT_STEPS = MappingProxyType({
    NextAction.START_CONTROLLER_THEN_CHECK: f'schtasks /Run /TN "{config.CONTROLLER_TASK}"; затем --l1-check',
    NextAction.START_CONTROLLER_THEN_INSTALL: f'Запустите вручную: schtasks /Run /TN "{config.CONTROLLER_TASK}"; '
                                              'затем повторите --l1-install',
    NextAction.INSTALL_BACKEND: 'Установите backend: --l1-backend-install PROFILE',
    NextAction.SAVE_CONNECTION_PROFILE: 'Сохраните ожидаемый выход: --connection-save FILE (шаблон '
                                        'examples/connection.example.json)',
    NextAction.CHECK_CONTROLLER_STATUS: 'Проверьте status.json контроллера',
    NextAction.CONFIRM_LIMITS: 'Прочитайте список и повторите с --confirm-l1-limits',
    NextAction.REINSTALL_CONTROLLER_TO_REPLACE: 'Установленный контроллер сохранён; для замены используйте '
                                                '--reinstall-controller',
    NextAction.SET_EXTENSION_PROXY: 'tools/vscode_claude_proxy.py set; затем Developer: Reload Window',
})
def explain_next(value: object) -> object:
    """The report with every named next step replaced by its command-line words."""
    if isinstance(value, dict):
        return {key: NEXT_STEPS[item] if isinstance(item, NextAction) else explain_next(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [explain_next(item) for item in value]
    return value
def require_report(args: argparse.Namespace, what: str) -> None:
    if not args.report:
        raise SafetyError(what + ' requires a result file')


def backend_profile_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .backend import profiles as backend_profiles
    if args.backend_import:
        return backend_profiles.import_profile(paths, args.backend_import)
    if args.backend_list:
        return backend_profiles.catalog(paths)
    return backend_profiles.status(paths, args.backend_status)


def isolation_audit_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .network.isolation_audit import audit
    return audit(paths)


def l1_check_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .network.l1_check import check
    return check(paths)


def l1_restart_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .network import l1_install
    payload = l1_install.restart(paths)
    payload['passed'] = payload.get('status') == Protection.RESTARTED
    return payload


def l1_remove_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .network import l1_remove
    payload = l1_remove.run(paths)
    payload['passed'] = payload.get('status') == Protection.REMOVED
    return payload


def l1_install_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .network import l1_install
    extension = True if args.protect_vscode_extension else False if args.exclude_vscode_extension else None
    payload = l1_install.run(paths, confirmed=args.confirm_l1_limits, protect_extension=extension,
                             reinstall_controller=args.reinstall_controller)
    payload['passed'] = payload.get('status') == Protection.INSTALLED
    return payload


def l1_backend_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .backend import install as backend_install
    if args.l1_backend_install:
        payload = backend_install.install(paths, args.l1_backend_install, archive=args.engine_archive)
    else:
        payload = backend_install.remove(paths)
    payload['passed'] = payload.get('status') in (Backend.INSTALLED, Backend.REMOVED)
    return payload


def package_serve_mode(args: argparse.Namespace, paths: Paths) -> dict:
    require_report(args, 'Package operations')
    from .network import package_isolation
    serve = package_isolation.register if args.l1_package_register_serve else package_isolation.remove
    return serve(args.report, paths=paths, request_id=args.uac_request_id)


def package_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .network import package_isolation
    if args.l1_package_register:
        return package_isolation.dispatch(paths, '--l1-package-register-serve', 'package-register-')
    return package_isolation.dispatch(paths, '--l1-package-remove-serve', 'package-remove-')


def autostart_serve_mode(args: argparse.Namespace, paths: Paths) -> dict:
    require_report(args, 'Autostart')
    from .network import autostart
    serve = autostart.install if args.strict_guard_autostart_serve else autostart.remove
    return serve(paths, args.report, request_id=args.uac_request_id)


def autostart_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .network import autostart
    return autostart.elevated(paths, enable=bool(args.strict_guard_autostart))


def remove_serve_mode(args: argparse.Namespace, paths: Paths) -> dict:
    require_report(args, 'Removal')
    if args.exclude_vscode_extension:
        from .network.extension_protection import remove_filters
        return remove_filters(paths, args.report, request_id=args.uac_request_id)
    from .network import controller
    return controller.remove(paths, args.report, request_id=args.uac_request_id)


def remove_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .network import controller
    return controller.elevated_remove(paths)


def l1_accept_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .network import l1_consent
    return l1_consent.accept(paths, args.confirm_l1_limits)


def l1_revoke_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .network import l1_consent
    return l1_consent.withdraw(paths)


def l1_status_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .network import l1_consent
    return l1_consent.report(paths)


def controller_serve_mode(args: argparse.Namespace, paths: Paths) -> dict:
    require_report(args, 'Strict controller')
    from .network import controller
    return controller.serve(paths, args.report, request_id=args.uac_request_id)


def controller_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .network import controller, controller_status, gate_rules
    action = (gate_rules.plan if args.strict_guard_plan else controller.elevated_start if args.strict_guard_start
              else controller.request_close if args.strict_guard_close else gate_rules.probe if args.strict_guard_probe
              else controller_status.status)
    return action(paths)


def connection_mode(args: argparse.Namespace, paths: Paths) -> dict:
    if args.connection_save:
        from .network import connections
        return connections.import_profile(paths, args.connection_save)
    from .network import remote_backend
    return remote_backend.check_saved(paths, include_router=args.include_router_proxy)


def legacy_guard_mode(args: argparse.Namespace, paths: Paths) -> dict:
    if args.network_guard_status:
        from .backend import location as backend_location
        return backend_location.status(paths)
    from .network import legacy_guard as netguard
    if args.network_guard_probe:
        return netguard.probe(paths)
    if args.network_guard_filters:
        return netguard.filter_receipt(paths, args.uac_request_id) if args.uac_request_id else netguard.filters()
    return netguard.guarded_launch(paths, args.network_guard_launch)


def privacy_audit_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .privacy.inventory import audit
    return audit(paths)


def code_extra_plan_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .reset.customizations import create_plan
    return create_plan(paths, args.source_entry)


def code_extra_apply_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .reset.customizations import apply_plan
    return apply_plan(paths, args.code_extra_apply, server_step_complete=args.server_step_complete)


def code_extra_recover_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .reset.customizations import recover
    destination = recover(paths, args.code_extra_recover)
    if sys.stdout:
        print('Source export: ' + str(destination))
    return {'status': Export.CUSTOMIZATION_SOURCE_EXPORTED, 'run': args.code_extra_recover}


def cowork_export_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .reset.cowork import create_export
    return create_export(paths, layout.desktop_data(paths), include_work=args.include_work)


def cowork_reset_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .reset.cowork import reset_exported
    return reset_exported(paths, args.cowork_reset, server_step_complete=args.server_step_complete)


def cowork_recover_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .reset.cowork import recover_export
    destination = recover_export(paths, args.cowork_recover)
    if sys.stdout:
        print('Cowork export: ' + str(destination))
    return {'status': Export.COWORK_EXPORT_RECOVERED, 'run': args.cowork_recover}


def desktop_key_plan_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .reset.desktop_keys import create_plan
    return create_plan(paths, layout.desktop_data(paths))


def desktop_key_apply_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .reset.desktop_keys import apply_plan
    return apply_plan(paths, args.desktop_key_apply, server_step_complete=args.server_step_complete)


def desktop_key_verify_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .reset.desktop_keys import verify_after_reset
    return verify_after_reset(paths, args.desktop_key_verify)


def native_selftest_mode(args: argparse.Namespace, paths: Paths) -> dict:
    from .reset.native import call_native
    return call_native(paths, 'selftest')


def reset_mode(args: argparse.Namespace, paths: Paths) -> dict:
    if args.policy:
        plan = policy_plan(paths, args.policy)
    else:
        plan = build_plan(paths, args.components.split(','),
                          selection=Selection(args.profile, args.project, args.privacy))
    if args.apply:
        return Executor(paths).apply(plan, consent_id=plan.id, server_step_complete=True)
    return plan.redacted()


def resume_mode(args: argparse.Namespace, paths: Paths) -> dict:
    return Executor(paths).resume(args.resume)


def recover_mode(args: argparse.Namespace, paths: Paths) -> dict:
    destination = recover_memory(paths, args.recover)
    if sys.stdout:
        print('Memory export: ' + str(destination))
    return {'status': Export.MEMORY_EXPORTED, 'run': args.recover}


def verification_template_mode(args: argparse.Namespace, paths: Paths) -> dict:
    return template_for_run(paths, args.verification_template)


def verify_run_mode(args: argparse.Namespace, paths: Paths) -> dict:
    return verify_run(paths, args.verify_run)


def record_verification_mode(args: argparse.Namespace, paths: Paths) -> dict:
    if args.record_verification.stat().st_size > 1_000_000:
        raise SafetyError('Verification file size limit exceeded')
    return save_evidence(paths, json.loads(args.record_verification.read_text('utf-8')))


# Every mode that runs without a window, in the order the flags are tried; the first set flag wins.
MODES = (
    (('backend_import', 'backend_status', 'backend_list'), backend_profile_mode),
    (('isolation_audit',), isolation_audit_mode),
    (('l1_check',), l1_check_mode),
    (('l1_restart',), l1_restart_mode),
    (('l1_remove',), l1_remove_mode),
    (('l1_install',), l1_install_mode),
    (('l1_backend_install', 'l1_backend_remove'), l1_backend_mode),
    (('l1_package_register_serve', 'l1_package_remove_serve'), package_serve_mode),
    (('l1_package_register', 'l1_package_remove'), package_mode),
    (('strict_guard_autostart_serve', 'strict_guard_autostart_off_serve'), autostart_serve_mode),
    (('strict_guard_autostart', 'strict_guard_autostart_off'), autostart_mode),
    (('strict_guard_remove_serve',), remove_serve_mode),
    (('strict_guard_remove',), remove_mode),
    (('l1_accept',), l1_accept_mode),
    (('l1_revoke',), l1_revoke_mode),
    (('l1_status',), l1_status_mode),
    (('strict_guard_serve',), controller_serve_mode),
    (('strict_guard_plan', 'strict_guard_start', 'strict_guard_status', 'strict_guard_close', 'strict_guard_probe'),
     controller_mode),
    (('connection_save', 'connection_check'), connection_mode),
    (('network_guard_status', 'network_guard_probe', 'network_guard_filters', 'network_guard_launch'),
     legacy_guard_mode),
    (('privacy_audit',), privacy_audit_mode),
    (('code_extra_plan',), code_extra_plan_mode),
    (('code_extra_apply',), code_extra_apply_mode),
    (('code_extra_recover',), code_extra_recover_mode),
    (('cowork_export',), cowork_export_mode),
    (('cowork_reset',), cowork_reset_mode),
    (('cowork_recover',), cowork_recover_mode),
    (('desktop_key_plan',), desktop_key_plan_mode),
    (('desktop_key_apply',), desktop_key_apply_mode),
    (('desktop_key_verify',), desktop_key_verify_mode),
    (('native_selftest',), native_selftest_mode),
    (('audit', 'apply'), reset_mode),
    (('resume',), resume_mode),
    (('recover',), recover_mode),
    (('verification_template',), verification_template_mode),
    (('verify_run',), verify_run_mode),
    (('record_verification',), record_verification_mode),
)


def chosen_mode(args: argparse.Namespace) -> Callable[[argparse.Namespace, Paths], dict] | None:
    """The handler of the first set mode flag, or None when the window should open."""
    return next((handler for flags, handler in MODES if any(getattr(args, flag) for flag in flags)), None)


def run_mode(args: argparse.Namespace, handler: Callable[[argparse.Namespace, Paths], dict]) -> int:
    """Run one command-line mode: print and save its report; exit code 2 when it is blocked or did not pass."""
    try:
        paths = Paths.current(args.state_root) if args.state_root is not None else Paths.current()
        payload = render(explain_next(handler(args, paths)), 'en')
        if args.report:
            atomic_json(args.report, payload, args.report.parent)
        if sys.stdout:
            # A legacy Windows console must not turn a successful operation into
            # a failed report merely because it cannot encode Russian text.
            print(json.dumps(payload, ensure_ascii=True, indent=2))
        return 2 if payload.get('blockers') or payload.get('passed') is False else 0
    except Exception as exc:
        from .elevation.claims import ChildAdmissionRefused
        payload = {'status': Reset.FAILED_OR_PARTIAL, 'error_type': type(exc).__name__, 'ready_for_new_account': False}
        if args.report and not isinstance(exc, ChildAdmissionRefused):
            try:
                atomic_json(args.report, payload, args.report.parent)
            except (OSError, SafetyError):
                # An unsafe/unwritable report path must not cause a second exception
                # that exposes command arguments or local paths in a traceback.
                if sys.stderr:
                    print('Report could not be written safely', file=sys.stderr)
        if sys.stderr:
            print(error_text(exc, 'ru') if isinstance(exc, SafetyError) else type(exc).__name__, file=sys.stderr)
        return 1


def command_line() -> argparse.ArgumentParser:
    """Every option of the program; without a mode option the main window opens."""
    parser = argparse.ArgumentParser(description='Claude Reset — scoped local reset and verification; default is GUI')
    modes = parser.add_mutually_exclusive_group()
    _reset_options(parser, modes)
    _network_options(parser, modes)
    parser.add_argument('--include-router-proxy', action='store_true',
                        help='Explicitly measure the configured router proxy before the local fallback')
    parser.add_argument('--source-entry', action='append', default=[],
                        help='Exact extra top-level Code entry to archive as user source')
    parser.add_argument('--include-work', action='store_true',
                        help='Include supported output artifacts in the Cowork export')
    parser.add_argument('--report', type=Path, help='Write a redacted JSON report')
    parser.add_argument('--policy', type=Path)
    parser.add_argument('--server-step-complete', action='store_true')
    parser.add_argument('--components', default='code,vscode,chrome')
    parser.add_argument('--profile', action='append', help='Exact discovered profile directory')
    parser.add_argument('--project', action='append', default=[])
    parser.add_argument('--privacy', choices=['compatible', 'strict'], default='compatible')
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--expert', action='store_true',
                        help='Open the specialist window with every tool instead of the main window')
    parser.add_argument('--uninstall', action='store_true',
                        help='Open the main window on removing the installed program')
    return parser


def _reset_options(parser, modes):
    """Archives, the reset and its verification, Desktop keys, Cowork and extra Code entries."""
    modes.add_argument('--state-inspect', action='store_true',
                       help='Discover archive locations without reading or moving their contents')
    modes.add_argument('--state-select', type=Path, metavar='PATH',
                       help='Persist one existing archive directory for GUI and CLI; no migration')
    parser.add_argument('--uac-request-id', help=argparse.SUPPRESS)
    parser.add_argument('--state-root', type=Path, help='Explicit absolute local archive directory for this invocation')
    modes.add_argument('--audit', action='store_true', help='Read-only inventory; no network calls')
    modes.add_argument('--privacy-audit', action='store_true',
                       help='Read-only privacy facts for standard local Code, VS Code and MSIX Desktop profiles; no '
                            'network calls')
    modes.add_argument('--apply', action='store_true', help='Apply a previously approved policy')
    modes.add_argument('--resume', metavar='RUN', help='Resume a known encrypted checkpoint')
    modes.add_argument('--recover', metavar='RUN', help='Export archived memory into a separate directory')
    modes.add_argument('--verification-template', metavar='RUN')
    modes.add_argument('--record-verification', type=Path)
    modes.add_argument('--verify-run', metavar='RUN', help='Compare known local identifiers using a run-scoped HMAC')
    modes.add_argument('--desktop-key-plan', action='store_true',
                       help='Create an encrypted review plan for primary MSIX Desktop application keys')
    modes.add_argument('--desktop-key-apply', metavar='RUN', help='Apply or continue an exact reviewed native key plan')
    modes.add_argument('--desktop-key-verify', metavar='RUN',
                       help='Observe the new client key and registration after a completed key reset')
    modes.add_argument('--native-selftest', action='store_true',
                       help='Create/delete unique synthetic TPM keys in the MSIX context')
    modes.add_argument('--cowork-export', action='store_true',
                       help='Inventory and encrypt Cowork memory and optionally outputs')
    modes.add_argument('--cowork-reset', metavar='RUN', help='Reset only Cowork session state after verified export')
    modes.add_argument('--cowork-recover', metavar='RUN',
                       help='Recover exported Cowork materials into a separate directory')
    modes.add_argument('--code-extra-plan', action='store_true',
                       help='Export selected extra Code sources and plan removal of all extra entries')
    modes.add_argument('--code-extra-apply', metavar='RUN')
    modes.add_argument('--code-extra-recover', metavar='RUN')


def _network_options(parser, modes):
    """The local guard, connection profiles, the L1 controller, backend and package, the isolation audit."""
    modes.add_argument('--network-guard-status', action='store_true',
                       help='Read-only check of the local Claude-only proxy guard; no network calls')
    modes.add_argument('--network-guard-probe', action='store_true',
                       help='Opt-in probe: direct TCP denied in Claude packages, HTTPS via the local proxy works')
    modes.add_argument('--network-guard-filters', action='store_true',
                       help='Read the owned WFP filters (run elevated); nothing is changed')
    modes.add_argument('--network-guard-launch', choices=['chrome', 'vscode'],
                       help='Report blocked launch: installed boundary and full release acceptance required')
    modes.add_argument('--connection-save', type=Path,
                       help='Validate JSON connection profile and store it encrypted; no network changes')
    modes.add_argument('--backend-import', type=Path,
                       help='Validate and encrypt an inactive tunnel profile; no process or network changes')
    modes.add_argument('--backend-status', metavar='ID',
                       help='Read redacted metadata of an imported inactive tunnel profile')
    modes.add_argument('--backend-list', action='store_true',
                       help='List encrypted inactive profiles without exposing credentials or starting a tunnel')
    modes.add_argument('--connection-check', action='store_true',
                       help='Measure the saved local proxy exit; never changes routes')
    modes.add_argument('--strict-guard-plan', action='store_true',
                       help='Prepare exact Windows deny/relay scope without applying it')
    modes.add_argument('--strict-guard-start', action='store_true',
                       help='Request UAC for the deny-first Windows controller')
    modes.add_argument('--strict-guard-serve', action='store_true', help=argparse.SUPPRESS)
    modes.add_argument('--strict-guard-status', action='store_true',
                       help='Read last controller report; not a live attestation')
    modes.add_argument('--strict-guard-probe', action='store_true',
                       help='Probe the live closed or relay-only package boundary')
    modes.add_argument('--strict-guard-close', action='store_true',
                       help='Request controller shutdown; persistent deny remains')
    modes.add_argument('--strict-guard-remove', action='store_true',
                       help='Request UAC to remove all owned deny/permit filters and proxy policy; stop the controller '
                            'first')
    modes.add_argument('--strict-guard-remove-serve', action='store_true', help=argparse.SUPPRESS)
    modes.add_argument('--strict-guard-autostart', action='store_true',
                       help='Request UAC once: install the logon task that starts the L1 controller from Program Files')
    modes.add_argument('--strict-guard-autostart-off', action='store_true',
                       help='Request UAC: remove the logon task and its Program Files copy')
    modes.add_argument('--strict-guard-autostart-serve', action='store_true', help=argparse.SUPPRESS)
    modes.add_argument('--strict-guard-autostart-off-serve', action='store_true', help=argparse.SUPPRESS)
    modes.add_argument('--l1-accept', action='store_true',
                       help='List the open L1 boundaries; with --confirm-l1-limits record your acceptance of exactly '
                            'those')
    modes.add_argument('--l1-revoke', action='store_true',
                       help='Remove the recorded L1 acceptance; the relay stays closed afterwards')
    modes.add_argument('--l1-status', action='store_true', help='Read the recorded L1 acceptance')
    modes.add_argument('--l1-restart', action='store_true',
                       help='Restart the installed L1 controller (no UAC); protected clients are offline for the '
                            'restart and the report says how long')
    modes.add_argument('--l1-remove', action='store_true',
                       help='Take L1 protection off this PC: controller, autostart, filters, backend, package, consent '
                            '(three UAC prompts)')
    modes.add_argument('--l1-install', action='store_true',
                       help='Install and start L1 protection step by step (needs the backend, a saved exit profile; '
                            'two UAC prompts; add --confirm-l1-limits)')
    parser.add_argument('--exclude-vscode-extension', action='store_true',
                        help='With --l1-install: keep Claude Code in the shared VS Code out of the protected set (the '
                             'default for a first install)')
    parser.add_argument('--reinstall-controller', action='store_true',
                        help='With --l1-install: replace an already installed controller (build and one UAC)')
    parser.add_argument('--protect-vscode-extension', action='store_true',
                        help='With --l1-install: also protect Claude Code in the shared VS Code (cuts running sessions '
                             'until the window is reloaded)')
    modes.add_argument('--l1-backend-install', type=Path, metavar='PROFILE',
                       help='No UAC: install the loopback tunnel backend from an owner-supplied profile file (format '
                            'of examples/backend.example.json)')
    modes.add_argument('--l1-backend-remove', action='store_true',
                       help='Stop and remove the backend this tool installed; refuses while the L1 relay is listening')
    parser.add_argument('--engine-archive', type=Path,
                        help='Offline install: local copy of the pinned engine archive instead of downloading it')
    modes.add_argument('--l1-package-register', action='store_true',
                       help='One UAC: register the ClaudeReset.NetworkIsolation identity package from the tracked '
                            'files')
    modes.add_argument('--l1-package-remove', action='store_true', help='One UAC: remove that package')
    modes.add_argument('--l1-package-register-serve', action='store_true', help=argparse.SUPPRESS)
    modes.add_argument('--l1-package-remove-serve', action='store_true', help=argparse.SUPPRESS)
    modes.add_argument('--l1-check', action='store_true',
                       help='Read-only readiness report for installing L1 on this PC; changes nothing, no network')
    parser.add_argument('--confirm-l1-limits', action='store_true',
                        help='Required together with --l1-accept to record acceptance')
    modes.add_argument('--isolation-audit', action='store_true',
                       help='Read Claude process tokens, descendants, Cowork presence and metadata visibility; no '
                            'network or client launch')


def state_mode(args: argparse.Namespace) -> int:
    """Find the folders that could hold the program's state, or choose one for the next runs."""
    try:
        payload = (layout.select(Path.home(), args.state_select) if args.state_select else
                   layout.inspect(Path.home(), layout.physical_local_appdata(), Path(os.environ['LOCALAPPDATA'])))
        if args.report:
            atomic_json(args.report, payload, args.report.parent)
        if sys.stdout:
            print(json.dumps(payload, ensure_ascii=True, indent=2))
        return 0
    except (SafetyError, OSError) as exc:
        if sys.stderr:
            print(error_text(exc, 'ru') if isinstance(exc, SafetyError) else type(exc).__name__, file=sys.stderr)
        return 1


def check_combinations(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Refuse option combinations the modes do not support; argparse exits with its usage error."""
    standard_scope = (not args.profile and not args.project and args.privacy == 'compatible'
                      and args.components == 'code,vscode,chrome')
    refused = (
        (args.include_router_proxy and not args.connection_check, '--include-router-proxy requires --connection-check'),
        (args.privacy_audit and (not standard_scope or args.policy),
         '--privacy-audit uses standard local profiles; use the GUI reviewed plan for other profiles'),
        (args.apply and (not args.policy or not args.server_step_complete),
         '--apply requires an approved --policy and fresh --server-step-complete'),
        (args.policy and not standard_scope, 'A saved policy cannot be expanded with command-line scope options'),
    )
    for condition, message in refused:
        if condition:
            parser.error(message)


def open_window(args: argparse.Namespace) -> int:
    """The main window, or the specialist window with --expert."""
    try:
        paths = Paths.current(args.state_root) if args.state_root is not None else Paths.current()
    except SafetyError:
        from tkinter import messagebox
        messagebox.showerror('ClaudeReset — хранилище состояния', gui_message('operation_failed'))
        return 1
    if args.expert:
        from .ui.expert_window import App
        App(paths=paths).mainloop()
    else:
        from .ui.shell import run
        run(paths, start='uninstall' if args.uninstall else None)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = command_line()
    args = parser.parse_args(argv)
    if (args.state_inspect or args.state_select) and args.state_root:
        parser.error('State discovery/selection cannot be combined with --state-root')
    if args.state_inspect or args.state_select:
        return state_mode(args)
    check_combinations(parser, args)
    handler = chosen_mode(args)
    if handler is not None:
        return run_mode(args, handler)
    return open_window(args)
