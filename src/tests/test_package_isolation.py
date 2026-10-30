import json
import shutil
import subprocess

import pytest

from claude_reset.network import legacy_guard as netguard, package_isolation as pkg
from claude_reset.safeio import SafetyError
from claude_reset import config

FAMILY = config.OWNED_PACKAGE[0]
FULL = 'ClaudeReset.NetworkIsolation_1.0.0.0_neutral__79st3xwgefr0c'


class Windows:
    """Stands in for powershell.exe: records scripts, answers Get-AppxPackage from `package`."""
    def __init__(self, package=None, add_fails=False):
        self.package, self.add_fails, self.scripts = package, add_fails, []

    def __call__(self, command, **kwargs):
        script = command[-1]
        self.scripts.append(script)
        if 'Get-AppxPackage' in script:
            out = '{}|{}|{}'.format(*self.package) if self.package else ''
            return subprocess.CompletedProcess(command, 0, out, '')
        if 'Add-AppxPackage' in script:
            if self.add_fails:
                return subprocess.CompletedProcess(command, 1, '', 'Deployment failed with HRESULT: 0x80073D2B')
            self.package = (FAMILY, FULL, pkg.PUBLISHER)
        if 'Remove-AppxPackage' in script:
            self.package = None
        return subprocess.CompletedProcess(command, 0, '', '')


@pytest.fixture
def sources():
    return pkg.source_directory()


def receipt(path):
    return json.loads(path.read_text('utf-8'))


def admitted_call(function, report, **kwargs):
    # Each independent domain scenario gets a real one-shot request. Failed
    # calls retain their claim; subsequent scenarios never erase it for retry.
    from types import SimpleNamespace
    from uuid import uuid4
    from claude_reset.elevation import request as uac
    root = report.parent / uuid4().hex
    paths = SimpleNamespace(state=root / 'state', local=root / 'local')
    operation = 'package-register' if function is pkg.register else 'package-remove'
    request = uac.prepare(paths, operation)
    return function(report, paths=paths, request_id=request.request_id, **kwargs)


def test_tracked_files_match_the_pinned_hashes(sources):
    pkg.verify_sources(sources)


def test_tampered_msix_is_refused_before_anything_is_registered(tmp_path, sources):
    folder = tmp_path / 'identity'
    shutil.copytree(sources, folder)
    (folder / 'identity.msix').write_bytes(b'tampered')
    windows = Windows()
    report = tmp_path / 'r.json'
    admitted_call(pkg.register, report, folder=folder, runtime=tmp_path / 'rt', runner=windows)
    assert receipt(report)['status'] == 'failed' and not any('Add-AppxPackage' in s for s in windows.scripts)
    assert not (tmp_path / 'rt').exists()


def test_register_stages_the_stub_and_uses_allow_unsigned_without_dev_mode(tmp_path, sources):
    windows, report = Windows(), tmp_path / 'r.json'
    admitted_call(pkg.register, report, folder=sources, runtime=tmp_path / 'rt', runner=windows)
    data = receipt(report)
    assert data['status'] == 'registered' and data['family'] == FAMILY
    assert data['developer_mode_changed'] is False and data['trusted_certificates_added'] is False
    add = next(s for s in windows.scripts if 'Add-AppxPackage' in s)
    assert '-AllowUnsigned' in add and '-ExternalLocation' in add and 'identity.msix' in add
    assert pkg.sha256(tmp_path / 'rt/identity-stub.exe') == pkg.STUB_SHA256
    assert not any('AppModelUnlock' in s or 'Import-Certificate' in s for s in windows.scripts)


def test_register_is_idempotent_and_never_overwrites(tmp_path, sources):
    windows = Windows(package=(FAMILY, FULL, pkg.PUBLISHER))
    report = tmp_path / 'r.json'
    admitted_call(pkg.register, report, folder=sources, runtime=tmp_path / 'rt', runner=windows)
    assert receipt(report)['status'] == 'already_registered'
    assert not any('Add-AppxPackage' in s for s in windows.scripts) and not (tmp_path / 'rt').exists()


def test_a_foreign_package_with_the_same_name_is_not_touched(tmp_path, sources):
    windows = Windows(package=(FAMILY, FULL, 'CN=Someone Else'))
    report = tmp_path / 'r.json'
    admitted_call(pkg.register, report, folder=sources, runtime=tmp_path / 'rt', runner=windows)
    assert receipt(report)['status'] == 'failed'
    admitted_call(pkg.remove, report, runtime=tmp_path / 'rt', runner=windows)
    assert receipt(report)['status'] == 'failed' and windows.package is not None
    assert not any('Remove-AppxPackage' in s for s in windows.scripts)


def test_windows_refusal_is_reported_with_its_reason(tmp_path, sources):
    report = tmp_path / 'r.json'
    admitted_call(pkg.register, report, folder=sources, runtime=tmp_path / 'rt', runner=Windows(add_fails=True))
    data = receipt(report)
    assert data['status'] == 'failed' and '0x80073D2B' in data['powershell_error']


def test_remove_deletes_only_the_matching_package_and_the_pinned_stub(tmp_path, sources):
    windows, report, runtime = Windows(), tmp_path / 'r.json', tmp_path / 'rt'
    admitted_call(pkg.register, report, folder=sources, runtime=runtime, runner=windows)
    (runtime / 'foreign.txt').write_text('keep')
    admitted_call(pkg.remove, report, runtime=runtime, runner=windows)
    assert receipt(report)['status'] == 'removed' and windows.package is None
    assert (runtime / 'foreign.txt').exists() and not (runtime / 'identity-stub.exe').exists()
    admitted_call(pkg.remove, report, runtime=runtime, runner=windows)        # nothing left: still a clean result
    assert receipt(report)['status'] == 'removed'


def test_accepted_requires_the_exact_family_and_publisher():
    assert pkg.accepted((FAMILY, FULL, pkg.PUBLISHER))
    assert not pkg.accepted((FAMILY, FULL, 'CN=Other'))
    assert not pkg.accepted(('Other_family', FULL, pkg.PUBLISHER))
    assert not pkg.accepted(None)


def test_child_receipt_identity(tmp_path, sources):
    from types import SimpleNamespace
    from claude_reset.elevation import request as uac
    paths = SimpleNamespace(state=tmp_path, local=tmp_path / 'local')
    report, windows = tmp_path / 'receipt.json', Windows()
    for operation, function, extra in (
        ('package-register', pkg.register, {'folder': sources}),
        ('package-remove', pkg.remove, {}),
    ):
        request = uac.prepare(paths, operation)
        function(report, runtime=tmp_path / 'rt', runner=windows,
                 paths=paths, request_id=request.request_id, **extra)
        row = receipt(report)
        assert row['operation'] == operation
        assert row['request_id'] == request.request_id
        assert row['state_root'] == str(tmp_path)
        assert row['finished'] is True
        uac.release(paths, request)
