"""Synthetic profiles and fake native APIs: public reports cannot assert readiness."""
import json
import pytest
from test_reset import paths
from test_customizations import customization
from test_cowork import setup_cowork
from test_native import native_setup
from claude_reset import customizations as cs,cowork as cw,desktop_keys as dk
from claude_reset.safeio import SafetyError

@pytest.mark.parametrize('kind',['customization','cowork','native'])
@pytest.mark.parametrize('failure',[False,True])
def test_specialized_apply_rebuilds_public_report(paths,request,monkeypatch,kind,failure):
    if kind=='customization':
        request.getfixturevalue('customization')
        report=cs.create_plan(paths,['scripts']);folder='customization-runs';apply=cs.apply_plan
    elif kind=='cowork':
        profile=request.getfixturevalue('setup_cowork')
        report=cw.create_export(paths,profile,include_work=True);folder='cowork-runs';apply=cw.reset_exported
    else:
        profile,_,_=request.getfixturevalue('native_setup')
        report=dk.create_plan(paths,profile);folder='key-runs';apply=dk.apply_plan
    run=report['run'];path=paths.state/folder/run/'result.json'
    report.update(ready_for_new_account=True,token='SENSITIVE_PUBLIC_REPORT_METADATA',network='verified')
    path.write_text(json.dumps(report),encoding='utf-8')
    if failure:
        def fail(*args,**kwargs):raise SafetyError('Synthetic operation failure')
        if kind in ('customization','cowork'):
            monkeypatch.setattr(cs if kind=='customization' else cw,'remove_owned',fail)
        else:
            original=dk.call_native
            def native(paths,operation,**kwargs):
                if operation=='delete':fail()
                return original(paths,operation,**kwargs)
            monkeypatch.setattr(dk,'call_native',native)
        with pytest.raises(SafetyError):apply(paths,run,server_step_complete=True)
        result=json.loads(path.read_text(encoding='utf-8'))
    else:result=apply(paths,run,server_step_complete=True)
    assert result['ready_for_new_account'] is False
    assert 'token' not in result and 'network' not in result
    assert result['run']==run and result['status']==('failed_or_partial' if failure else 'completed')
    assert json.loads(path.read_text(encoding='utf-8'))==result
