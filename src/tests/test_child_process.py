"""Temporary admission records only; no elevation or client effects."""
from dataclasses import asdict
import json

import pytest

from claude_reset.elevation import child_process as child, request as uac
from claude_reset.elevation import claims
from test_uac_request import paths


@pytest.mark.parametrize('failure', ['generation', 'before-write', 'torn-write'])
def test_record_failure_refuses_handler_and_keeps_consumption(paths, monkeypatch, failure):
    request = uac.prepare(paths, 'remove')
    save = claims.save_exclusive
    def fail(path, row):
        if path.name.startswith('process-'):
            if failure == 'torn-write': path.write_text('{')
            raise OSError('private error')
        save(path, row)
    if failure == 'generation':
        monkeypatch.setattr(child.controller_process, 'generation',
                            lambda pid: (_ for _ in ()).throw(OSError('private error')))
    else:
        monkeypatch.setattr(claims, 'save_exclusive', fail)
    with pytest.raises(claims.ChildAdmissionRefused):
        uac.admit_child(paths, 'remove', request.request_id)
    assert (paths.state / 'strict-guard' / ('admitted-' + request.request_id + '.json')).exists()
    with pytest.raises(claims.ChildAdmissionRefused):
        uac.admit_child(paths, 'remove', request.request_id)
    assert claims.blocked(paths)


@pytest.mark.parametrize('operation', sorted(claims.OPERATIONS - {'start'}))
def test_all_noncontroller_admissions_record_current_process(paths, operation):
    import os
    request = uac.prepare(paths, operation)
    uac.admit_child(paths, operation, request.request_id)
    row = json.loads(child.witness_path(request).read_text())
    assert row['request'] == asdict(request) and row['pid'] == os.getpid()
