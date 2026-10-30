"""Register and remove the ClaudeReset.NetworkIsolation identity package from the tracked files.

The package gives processes started inside it the identity that the L1 deny rules name. It is an
unsigned MSIX with an external location, registered with `Add-AppxPackage -AllowUnsigned`; no
certificate is trusted and Developer Mode is not changed. Both operations need elevation and run
only through the one-UAC relaunch of the CLI. Files are pinned by SHA-256 and registration never
overwrites an existing package.
"""
import hashlib
import shutil
import sys
from pathlib import Path

from ..errors import SafetyError
from ..safeio import atomic_json
from .. import config
from .. import layout
from ..windows.powershell import run as powershell
from ..errors import error_info
from ..model.status import Package
from ..model.ids import utc_now

PUBLISHER = 'CN=ClaudeResetLocal, OID.2.25.311729368913984317654407730594956997722=1'
MSIX_SHA256 = '2a256d50ff61c02edb15daa8564e3f9772e8e07387b2e70e34acc6c8b196d88a'
STUB_SHA256 = '48081c14005cc8b99a43143f102b4dec709fc89e39f3eaa2954d4d637091cd6f'
RUNTIME_NAME = 'identity-runtime'
NO_WINDOW = 0x08000000


def source_directory():
    """The tracked packaging folder next to the sources, or next to a frozen executable."""
    for base in (layout.PROGRAM_DIR, Path(sys.executable).resolve().parent):
        candidate = base / 'packaging' / 'identity'
        if (candidate / 'identity.msix').is_file():
            return candidate
    raise SafetyError('Packaging files were not found next to the program')


def runtime_directory():
    return layout.l1_program() / RUNTIME_NAME


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_sources(folder):
    if sha256(folder / 'identity.msix') != MSIX_SHA256 or sha256(folder / 'identity-stub.exe') != STUB_SHA256:
        raise SafetyError('Packaging files differ from the pinned versions; nothing was registered')


def installed(runner=None):
    """Return one identity or confirmed absence; unreadable state raises.

    Never turn a failed query or ambiguous inventory into permission to stage
    or delete package files.
    """
    code, out, _ = powershell(
        f"Get-AppxPackage -Name '{config.OWNED_PACKAGE_NAME}' | ForEach-Object {{ "
        "'{0}|{1}|{2}' -f $_.PackageFamilyName, $_.PackageFullName, $_.Publisher }; exit 0", runner)
    if code:
        raise SafetyError('Package registration state unavailable')
    if not out:
        return None
    rows = out.splitlines()
    if len(rows) != 1:
        raise SafetyError('Package registration state ambiguous')
    fields = rows[0].split('|')
    if len(fields) != 3 or any(not field.strip() for field in fields):
        raise SafetyError('Package registration state invalid')
    family, full, publisher = fields
    # Full name is interpolated into the fixed removal command.
    if any(not (c.isascii() and (c.isalnum() or c in '._-~')) for c in full):
        raise SafetyError('Package full name invalid')
    return family, full, publisher


def accepted(found):
    return bool(found) and found[0] == config.OWNED_PACKAGE[0] and found[2] == PUBLISHER and found[1].startswith(config.OWNED_PACKAGE_NAME + '_')


def register(report_path, *, folder=None, runtime=None, runner=None, paths=None, request_id=None):
    """Elevated. Idempotent: an already registered, matching package is reported and left untouched."""
    result = {'schema': 1, 'finished': False, 'action': 'register', 'utc': utc_now(),
              'developer_mode_changed': False, 'trusted_certificates_added': False}
    from ..elevation.request import admit_child, child_event
    result.update(admit_child(paths, 'package-register', request_id))
    try:
        folder = folder or source_directory()
        verify_sources(folder)
        found = installed(runner)
        if found:
            if not accepted(found):
                raise SafetyError('A different package with this name is registered; it was not touched')
            result.update(status=Package.ALREADY_REGISTERED, family=found[0], full_name=found[1])
        else:
            target = runtime or runtime_directory()
            target.mkdir(parents=True, exist_ok=True)
            stub = target / 'identity-stub.exe'
            shutil.copyfile(folder / 'identity-stub.exe', stub)
            if sha256(stub) != STUB_SHA256:
                raise SafetyError('The staged stub differs from the pinned file')
            code, _, error = powershell(
                f"Add-AppxPackage -Path '{folder / 'identity.msix'}' -ExternalLocation '{target}' -AllowUnsigned", runner)
            if code:
                result['powershell_error'] = error
                raise SafetyError('Package registration was refused by Windows')
            found = installed(runner)
            if not accepted(found):
                raise SafetyError('The registered package does not match the expected identity')
            result.update(status=Package.REGISTERED, family=found[0], full_name=found[1])
    except Exception as exc:
        result.update(status=Package.FAILED, error=error_info(exc))
    result['finished'] = True
    child_event(paths, {key: result[key] for key in ('request_id', 'operation', 'state_root')}, 'finish')
    atomic_json(report_path, result, report_path.parent)
    return result


def remove(report_path, *, runtime=None, runner=None, paths=None, request_id=None):
    """Elevated. Removes only a package whose identity matches exactly, then its staged stub."""
    result = {'schema': 1, 'finished': False, 'action': 'remove', 'utc': utc_now()}
    from ..elevation.request import admit_child, child_event
    result.update(admit_child(paths, 'package-remove', request_id))
    try:
        found = installed(runner)
        if found:
            if not accepted(found):
                raise SafetyError('A different package with this name is registered; it was not touched')
            code, _, error = powershell(f"Remove-AppxPackage -Package '{found[1]}'", runner)
            if code:
                result['powershell_error'] = error
                raise SafetyError('Package removal was refused by Windows')
        # Verify before deleting the executable the package may still refer to.
        # Keep one snapshot for both status and registered_after.
        after = installed(runner)
        result['registered_after'] = after is not None
        if after is not None:
            raise SafetyError('Package remains registered; runtime files preserved')
        target = runtime or runtime_directory()
        stub = target / 'identity-stub.exe'
        if stub.is_file() and sha256(stub) == STUB_SHA256:
            stub.unlink()
        if target.is_dir() and not any(target.iterdir()):
            target.rmdir()
        if runtime is None and target.parent.is_dir() and not any(target.parent.iterdir()):
            target.parent.rmdir()                      # the shared ClaudeReset-L1 folder, once nothing else is in it
        result.update(status=Package.REMOVED)
    except Exception as exc:
        result.update(status=Package.FAILED, error=error_info(exc))
    result['finished'] = True
    child_event(paths, {key: result[key] for key in ('request_id', 'operation', 'state_root')}, 'finish')
    atomic_json(report_path, result, report_path.parent)
    return result


def dispatch(paths, serve_flag, prefix, *, wait_seconds=240, prompt=None):
    """Use the shared claim and exact receipt, including inside an L1 chain.

    prompt shows the UAC prompt for the prepared request (launch.dispatch_request when not given)."""
    from ..elevation import launch, request as uac_request
    operations = {'--l1-package-register-serve': 'package-register',
                  '--l1-package-remove-serve': 'package-remove'}
    if serve_flag not in operations:
        raise SafetyError('Unsupported package operation')
    return uac_request.execute(paths, operations[serve_flag],
                               prompt or launch.dispatch_request, wait_seconds=wait_seconds)
