"""Only a durable private completion can authorize post-reset observations."""
import json

import pytest
from test_native import ACCOUNT, OTHER, key, native_setup
from test_reset import paths, write

from claude_reset.reset import desktop_keys as dk
from claude_reset.safeio import SafetyError


def replacement(profile,inventory):
    inventory['keys']=[key(OTHER,digest='b'*64)]
    write(profile/dk.FILES[0],json.dumps({OTHER:'pk1:'+'b'*64+':'+ACCOUNT}))


def test_public_completion_does_not_authorize_observation(paths,native_setup,monkeypatch):
    profile,inventory,calls,desktop=native_setup
    result=dk.create_plan(paths,profile, desktop=desktop);run=result['run']
    result['status']='completed'
    (paths.state/'key-runs'/run/'result.json').write_text(json.dumps(result))
    replacement(profile,inventory)
    observed=[];original=desktop.answers['native']
    def native(*args,**kwargs):
        observed.append(True);return original(*args,**kwargs)
    desktop.answers['native']=native
    with pytest.raises(SafetyError):dk.verify_after_reset(paths,run, desktop=desktop)
    assert not calls and not observed


def test_completed_private_reset_survives_missing_public_report(paths,native_setup):
    profile,inventory,calls,desktop=native_setup
    result=dk.create_plan(paths,profile, desktop=desktop);run=result['run']
    dk.apply_plan(paths,run,server_step_complete=True, desktop=desktop)
    (paths.state/'key-runs'/run/'result.json').unlink()
    replacement(profile,inventory)
    result=dk.verify_after_reset(paths,run, desktop=desktop)
    assert result['new_registered_public_key_verified'] is True
    assert result['ready_for_new_account'] is False and len(calls)==1


@pytest.mark.parametrize('fault',['legacy','schema','next','next-bool','pending','files','marker'])
def test_private_completion_requires_consistent_progress(paths,native_setup,monkeypatch,fault):
    profile,inventory,calls,desktop=native_setup
    result=dk.create_plan(paths,profile, desktop=desktop);run=result['run']
    dk.apply_plan(paths,run,server_step_complete=True, desktop=desktop)
    path=paths.state/'key-runs'/run/'plan.dpapi'
    plan=dk.private_read(paths,path)
    if fault=='legacy':plan.pop('reset_completed')
    elif fault=='schema':plan['schema']=True
    elif fault=='next':plan['next']=0
    elif fault=='next-bool':plan['next']=True
    elif fault=='pending':plan['in_progress']=0
    elif fault=='files':plan['files_done']=[]
    else:plan['reset_completed']=1
    dk.private_write(paths,path,plan)
    observed=[]
    desktop.answers['native']=lambda *a,**kw:observed.append(True)
    with pytest.raises(SafetyError):dk.verify_after_reset(paths,run, desktop=desktop)
    assert not observed


def test_private_completion_blocks_replay_with_forged_public_report(paths,native_setup,monkeypatch):
    profile,inventory,calls,desktop=native_setup
    result=dk.create_plan(paths,profile, desktop=desktop);run=result['run']
    dk.apply_plan(paths,run,server_step_complete=True, desktop=desktop)
    (paths.state/'key-runs'/run/'result.json').write_text(json.dumps(result))
    replacement(profile,inventory);observed=[]
    desktop.answers['native']=lambda *a,**kw:observed.append(True)
    with pytest.raises(SafetyError):dk.apply_plan(paths,run,server_step_complete=True, desktop=desktop)
    assert not observed and len(calls)==1 and len(inventory['keys'])==1


def test_failed_private_completion_write_is_resumable_without_repeat_delete(paths,native_setup,monkeypatch):
    profile,inventory,calls,desktop=native_setup
    result=dk.create_plan(paths,profile, desktop=desktop);run=result['run']
    original=dk.private_write
    def fail(paths,path,value):
        if value.get('reset_completed') is True:raise OSError('synthetic checkpoint failure')
        return original(paths,path,value)
    monkeypatch.setattr(dk,'private_write',fail)
    with pytest.raises(SafetyError):dk.apply_plan(paths,run,server_step_complete=True, desktop=desktop)
    assert len(calls)==1
    with pytest.raises(SafetyError):dk.verify_after_reset(paths,run, desktop=desktop)
    monkeypatch.setattr(dk,'private_write',original)
    assert dk.apply_plan(paths,run,server_step_complete=True, desktop=desktop)['status']=='completed'
    assert len(calls)==1


def test_completed_private_checkpoint_survives_report_write_failure(paths,native_setup,monkeypatch):
    profile,inventory,calls,desktop=native_setup
    result=dk.create_plan(paths,profile, desktop=desktop);run=result['run'];original=dk.atomic_json
    def fail(path,value,root):
        if value.get('status')=='completed':raise OSError('synthetic report failure')
        return original(path,value,root)
    monkeypatch.setattr(dk,'atomic_json',fail)
    with pytest.raises(SafetyError):dk.apply_plan(paths,run,server_step_complete=True, desktop=desktop)
    replacement(profile,inventory)
    assert dk.verify_after_reset(paths,run, desktop=desktop)['new_registered_public_key_verified'] is True
    with pytest.raises(SafetyError):dk.apply_plan(paths,run,server_step_complete=True, desktop=desktop)
    assert len(calls)==1
