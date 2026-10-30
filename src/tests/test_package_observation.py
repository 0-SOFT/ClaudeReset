"""Package contracts with temporary files and a fake PowerShell runner only."""
import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_package_isolation import FAMILY, FULL, Windows

from claude_reset.elevation import claims
from claude_reset.elevation import request as uac
from claude_reset.network import package_isolation as pkg
from claude_reset.safeio import SafetyError

ROW = f'{FAMILY}|{FULL}|{pkg.PUBLISHER}'


@pytest.mark.parametrize('code,out', [
    (1, ''), (1, ROW), (0, 'malformed'), (0, ROW + '\n' + ROW),
    (0, '|name|publisher'), (0, 'family||publisher'), (0, 'family|name|'),
    (0, ROW + '|extra'), (0, "family|name'; exit 0; '|publisher"),
])
def test_unknown_inventory_is_never_absence(code, out):
    def runner(command, **kwargs):
        assert 'Select-Object -First' not in command[-1]
        return subprocess.CompletedProcess(command, code, out, 'private fixture')
    with pytest.raises(SafetyError) as error:
        pkg.installed(runner)
    assert 'private' not in str(error.value)


@pytest.mark.parametrize('package', [None, (FAMILY, FULL, pkg.PUBLISHER)])
def test_confirmed_absence_and_identity(package):
    assert pkg.installed(Windows(package)) == package


class Observations(Windows):
    def __init__(self, observations):
        super().__init__((FAMILY, FULL, pkg.PUBLISHER))
        self.observations = iter(observations)
        self.queries = 0

    def __call__(self, command, **kwargs):
        if 'Get-AppxPackage' in command[-1]:
            self.scripts.append(command[-1])
            self.queries += 1
            item = next(self.observations)
            if isinstance(item, Exception):
                raise item
            code, out = item
            return subprocess.CompletedProcess(command, code, out, 'private query error')
        return super().__call__(command, **kwargs)


def invoke(tmp_path, operation, runner):
    paths = SimpleNamespace(state=tmp_path / 'state', local=tmp_path / 'local')
    request = uac.prepare(paths, operation)
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    shutil.copyfile(pkg.source_directory() / 'identity-stub.exe', runtime / 'identity-stub.exe')
    before = (runtime / 'identity-stub.exe').read_bytes()
    report = Path(request.receipt)
    function = pkg.register if operation == 'package-register' else pkg.remove
    extra = {'folder': pkg.source_directory()} if operation == 'package-register' else {}
    result = function(report, paths=paths, request_id=request.request_id,
                      runtime=runtime, runner=runner, **extra)
    assert json.loads(report.read_text('utf-8')) == result
    assert uac.read_receipt(request) == result
    assert uac.verdict(request, result) == (
        'reconcile_required' if result['status'] == 'failed' else 'completed')
    return paths, request, runtime, before, result


@pytest.mark.parametrize('operation', ['package-register', 'package-remove'])
@pytest.mark.parametrize('observation', [(1, ''), (0, 'malformed'),
                                         subprocess.TimeoutExpired('fixture', 1)])
def test_unknown_before_operation_preserves_files_and_claim(tmp_path, operation, observation):
    runner = Observations([observation])
    paths, request, runtime, before, result = invoke(tmp_path, operation, runner)
    assert result['status'] == 'failed'
    assert (runtime / 'identity-stub.exe').read_bytes() == before
    assert not any('Remove-AppxPackage' in s or 'Add-AppxPackage' in s for s in runner.scripts)
    assert claims.blocked(paths)


@pytest.mark.parametrize('after', [(1, ''), (0, 'malformed'), (0, ROW),
                                   (0, f'{FAMILY}|{FULL}|CN=Foreign')])
def test_remove_requires_absence_before_cleanup(tmp_path, after):
    runner = Observations([(0, ROW), after])
    paths, request, runtime, before, result = invoke(tmp_path, 'package-remove', runner)
    assert result['status'] == 'failed'
    assert (runtime / 'identity-stub.exe').read_bytes() == before
    assert runner.queries == 2
    assert sum('Remove-AppxPackage' in s for s in runner.scripts) == 1
    assert claims.blocked(paths)
    assert result.get('registered_after') is not False


def test_remove_uses_one_verified_postcondition_before_cleanup(tmp_path):
    runner = Observations([(0, ROW), (0, '')])
    paths, request, runtime, before, result = invoke(tmp_path, 'package-remove', runner)
    assert result['status'] == 'removed' and result['registered_after'] is False
    assert not runtime.exists()
    assert runner.queries == 2


@pytest.mark.parametrize('after', [(1, ''), (0, ''), (0, 'malformed'),
                                   (0, f'{FAMILY}|{FULL}|CN=Foreign')])
def test_register_requires_matching_postcondition(tmp_path, after):
    runner = Observations([(0, ''), after])
    paths, request, runtime, before, result = invoke(tmp_path, 'package-register', runner)
    assert result['status'] == 'failed' and claims.blocked(paths)
    assert sum('Add-AppxPackage' in s for s in runner.scripts) == 1
    assert (runtime / 'identity-stub.exe').read_bytes() == before


