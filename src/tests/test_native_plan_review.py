"""Confirmation counts come from the private plan, without calling native deletion."""
import json
from types import SimpleNamespace

import pytest
from dialog_fakes import Dialogs
from test_native import native_setup
from test_reset import paths

from claude_reset.reset import desktop_keys as dk
from claude_reset.safeio import SafetyError
from claude_reset.ui.expert.settings import SettingsTab


@pytest.mark.parametrize('public_report',['forged','missing'])
def test_native_gui_confirmation_uses_private_plan(paths,native_setup,monkeypatch,public_report):
    profile,inventory,calls,desktop=native_setup
    report=dk.create_plan(paths,profile, desktop=desktop);run=paths.state/'key-runs'/report['run']
    if public_report=='forged':
        report.update(accounts=999,keys=999)
        (run/'result.json').write_text(json.dumps(report),encoding='utf-8')
    else:(run/'result.json').unlink()
    prompts=[]
    dialogs=Dialogs(askopenfilename=lambda **kw:str(run/'plan.dpapi'),
                    askyesno=lambda title,text:prompts.append(text) or False)
    app=SimpleNamespace(paths=paths,server_done=SimpleNamespace(get=lambda:True),
                        run=lambda action,callback:callback(action()),show_json=lambda value:None,dialogs=dialogs,
                        desktop=desktop)
    SettingsTab(app).apply_desktop_keys()
    assert len(prompts)==1 and ': аккаунтов 1, ключей 1.' in prompts[0]
    assert not calls and len(inventory['keys'])==1

@pytest.mark.parametrize('fault',['schema','id','accounts','keys','inventory','count'])
def test_native_review_rejects_invalid_private_checkpoint(paths,native_setup,fault):
    profile,_,calls,desktop=native_setup;report=dk.create_plan(paths,profile, desktop=desktop)
    file=paths.state/'key-runs'/report['run']/'plan.dpapi';plan=dk.private_read(paths,file)
    if fault=='schema':plan['schema']=True
    elif fault=='id':plan['id']='0'*32
    elif fault=='count':plan['inventory']['keys']=[]
    else:plan[fault]='invalid'
    dk.private_write(paths,file,plan)
    with pytest.raises(SafetyError):dk.review_plan(paths,report['run'])
    assert not calls
