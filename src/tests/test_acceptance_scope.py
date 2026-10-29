"""Manual acceptance stays bound to its private run and a closed vocabulary."""
import json
import pytest
from test_reset import paths,FakeCrypto,apply
from test_features import plan
from claude_reset import verification as v
from claude_reset.safeio import SafetyError

@pytest.mark.parametrize('components',[None,[],['SENSITIVE_REPORT_FIELD'],['code','code'],('code',),{'token':'value'},[True]])
def test_template_rejects_unreviewed_scope(components):
    with pytest.raises(SafetyError):v.template('a'*32,components)


def test_template_rejects_boolean_schema():
    with pytest.raises(SafetyError):v.template('a'*32,['code'],schema=True)


def test_public_report_cannot_change_manual_evidence_scope(paths,monkeypatch):
    p=plan(paths,('chrome',));apply(paths,p)
    file=paths.state/'runs'/p.id/'result.json'
    result=json.loads(file.read_text());result['components']=['code'];file.write_text(json.dumps(result))
    monkeypatch.setattr('claude_reset.execution.DPAPI',FakeCrypto)
    with pytest.raises(SafetyError):v.save_evidence(paths,v.template(p.id,['code']))
    assert not (file.parent/'acceptance.json').exists()


@pytest.mark.parametrize('public',['missing','malformed','forged'])
def test_template_and_evidence_use_private_scope(paths,public):
    p=plan(paths,('chrome',));apply(paths,p)
    file=paths.state/'runs'/p.id/'result.json'
    if public=='missing':file.unlink()
    else:file.write_text('invalid json' if public=='malformed' else json.dumps({'components':['SENSITIVE_REPORT_FIELD']}))
    evidence=v.template_for_run(paths,p.id,FakeCrypto())
    assert evidence['components']==['chrome'] and 'SENSITIVE_REPORT_FIELD' not in json.dumps(evidence)
    result=v.save_evidence(paths,evidence,FakeCrypto())
    assert result['ready_for_new_account'] is False and result['components']==['chrome']


@pytest.mark.parametrize('fault',['schema','id','scope','missing'])
def test_private_scope_failure_does_not_write_evidence(paths,fault):
    from claude_reset.execution import Executor
    p=plan(paths,('chrome',));apply(paths,p)
    file=paths.state/'runs'/p.id/'journal.dpapi';executor=Executor(paths,FakeCrypto())
    if fault=='missing':file.unlink()
    else:
        journal=executor._read_private(file)
        if fault=='schema':journal['schema']=True
        elif fault=='id':journal['plan']['id']='0'*32
        else:journal['plan']['components']=['SENSITIVE_REPORT_FIELD']
        executor._write_private(file,journal)
    with pytest.raises((SafetyError,FileNotFoundError)):v.save_evidence(paths,v.template(p.id,['chrome']),FakeCrypto())
    assert not (file.parent/'acceptance.json').exists()


def test_gui_template_ignores_forged_public_scope(paths,monkeypatch):
    from types import SimpleNamespace
    from claude_reset.app import App
    p=plan(paths,('chrome',));apply(paths,p)
    file=paths.state/'runs'/p.id/'result.json';file.write_text(json.dumps({'components':['SENSITIVE_REPORT_FIELD']}))
    output=paths.home/'acceptance.json'
    monkeypatch.setattr('claude_reset.app.filedialog.asksaveasfilename',lambda **kw:str(output))
    monkeypatch.setattr('claude_reset.execution.DPAPI',FakeCrypto)
    App.acceptance_template(SimpleNamespace(paths=paths,last_run=p.id,safe=lambda action:action()))
    assert json.loads(output.read_text())['components']==['chrome']


def test_cli_template_uses_private_scope(paths,monkeypatch,capsys):
    from claude_reset import app
    p=plan(paths,('chrome',));apply(paths,p)
    (paths.state/'runs'/p.id/'result.json').unlink()
    monkeypatch.setattr(app.Paths,'current',classmethod(lambda cls,*args:paths))
    monkeypatch.setattr('claude_reset.execution.DPAPI',FakeCrypto)
    assert app.main(['--verification-template',p.id])==0
    assert json.loads(capsys.readouterr().out)['components']==['chrome']
