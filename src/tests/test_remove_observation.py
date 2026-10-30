"""Removal postconditions with fake WFP/registry and temporary receipts only."""
import winreg
from pathlib import Path
from types import SimpleNamespace

import pytest
from wfp_fakes import fake

from claude_reset import config
from claude_reset.elevation import claims
from claude_reset.elevation import request as uac
from claude_reset.network import controller as guard
from claude_reset.network.strict_wfp import Engine as StrictEngine


@pytest.mark.parametrize('fault', [None, 'sublayer', 'filters', 'wfp-read',
                                  'user-policy', 'machine-policy', 'policy-read', 'foreign'])
def test_remove_requires_observed_resource_absence(tmp_path, monkeypatch, fault):
    calls = []

    class Engine(fake(StrictEngine)):
        committed = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def existing_sublayer(self):
            if self.committed and fault == 'wfp-read':
                raise PermissionError('fixture')
            return not self.committed or fault == 'sublayer'

        def own_keys(self):
            return {'00000000-0000-0000-0000-000000000001'} if (
                not self.committed or fault == 'filters') else set()

        def native(self, name, *args, **kwargs):
            calls.append(name)
            if name == 'FwpmTransactionCommit0':
                self.committed = True

    values = {winreg.HKEY_CURRENT_USER: (config.RELAY_URL, winreg.REG_SZ),
              winreg.HKEY_LOCAL_MACHINE: (config.RELAY_URL, winreg.REG_SZ)}
    if fault == 'foreign':
        values[winreg.HKEY_CURRENT_USER] = ('foreign-proxy', winreg.REG_SZ)
    reads = {}

    class Key:
        def __init__(self, hive):
            self.hive = hive

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def query(key, name):
        assert name == 'egressProxyUrl'
        reads[key.hive] = reads.get(key.hive, 0) + 1
        if reads[key.hive] > 1 and fault == 'policy-read':
            raise PermissionError('fixture')
        if key.hive not in values:
            raise FileNotFoundError()
        return values[key.hive]

    def delete(key, name):
        calls.append(('delete-policy', key.hive))
        retained = {'user-policy': winreg.HKEY_CURRENT_USER,
                    'machine-policy': winreg.HKEY_LOCAL_MACHINE}.get(fault)
        if key.hive != retained:
            del values[key.hive]

    monkeypatch.setattr(winreg, 'OpenKey', lambda hive, *args: Key(hive))
    monkeypatch.setattr(winreg, 'QueryValueEx', query)
    monkeypatch.setattr(winreg, 'DeleteValue', delete)
    paths = SimpleNamespace(state=tmp_path / 'state', local=tmp_path / 'local')
    request = uac.prepare(paths, 'remove')
    result = guard.remove(paths, Path(request.receipt), request_id=request.request_id, engine=Engine)
    assert uac.read_receipt(request) == result
    successful = fault in (None, 'foreign')
    assert (result.get('removed') is True) == successful
    assert uac.verdict(request, result) == ('completed' if successful else 'reconcile_required')
    assert claims.blocked(paths)  # A resource snapshot does not release ownership.
    if successful:
        assert result['sublayer_present_after'] is False
        assert result['filters_remaining_after'] == 0
        assert result['policy_values_remaining_after'] == []
    if fault == 'foreign':
        assert values[winreg.HKEY_CURRENT_USER] == ('foreign-proxy', winreg.REG_SZ)
        assert ('delete-policy', winreg.HKEY_CURRENT_USER) not in calls
    if fault in ('sublayer', 'filters', 'wfp-read'):
        assert not reads
