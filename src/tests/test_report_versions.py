"""Client-controlled version metadata must not become diagnostic report content."""
import dataclasses
import json

import pytest
from test_reset import FakeCrypto, paths, platform

from claude_reset.reset.execution import Executor
from claude_reset.reset.planner import build_plan


@pytest.mark.parametrize('field', ['cli_version','extension_versions','desktop_versions'])
def test_report_rejects_nonversion_metadata(paths,field):
    state=platform();secret='SENSITIVE_METADATA_TOKEN_9743 C:/Users/Private/profile'
    state[field]=secret if field=='cli_version' else [secret]
    plan=build_plan(paths,('code',),platform_state=state,env={})
    original=json.dumps(plan.versions)
    assert secret in original
    assert secret not in json.dumps(plan.redacted())
    assert json.dumps(plan.versions)==original

def test_report_preserves_numeric_versions_without_approving_them(paths):
    (paths.home/'.claude').mkdir()
    state=platform();state['cli_version']='9.9.9';state['extension_versions']=['2.1.310']
    state['desktop_versions']=['3.6556.2.0']
    plan=build_plan(paths,('code',),platform_state=state,env={})
    assert plan.redacted()['versions']=={'cli':'9.9.9','extension':['2.1.310'],'desktop':['3.6556.2.0']}
    assert any('version' in reason for reason in plan.blockers)

@pytest.mark.parametrize('value',['1.2.3\nSECRET_METADATA', '1.'+'2'*5000, {'token':'SECRET_METADATA'}, True],
                         ids=['newline','oversize','object','boolean'])
def test_report_handles_malformed_version_values(paths,value):
    plan=build_plan(paths,('code',),platform_state=platform(),env={})
    plan=dataclasses.replace(plan,versions={'cli':value,'extension':[value],'desktop':[value],'SECRET_METADATA':'private'})
    report=plan.redacted()['versions']
    assert report=={'cli':'unknown','extension':['unknown'],'desktop':['unknown']}

@pytest.mark.parametrize('resume',[False,True])
def test_execution_reports_redact_unselected_client_metadata(paths,resume):
    secret='SENSITIVE_UNSELECTED_VERSION_METADATA_9137'
    state=platform();state['cli_version']=secret
    plan=build_plan(paths,('chrome',),platform_state=state,env={})
    executor=Executor(paths,FakeCrypto(),lambda:state)
    result=executor.apply(plan,consent_id=plan.id,server_step_complete=True)
    report_path=paths.state/'runs'/plan.id/'result.json'
    if resume:
        # Existing reports from earlier builds must be cleaned on continuation.
        result['versions']=plan.versions
        report_path.write_text(json.dumps(result),encoding='utf-8')
        result=executor.resume(plan.id)
    assert secret not in json.dumps(result)
    assert secret not in report_path.read_text(encoding='utf-8')
    assert plan.versions['cli']==secret

@pytest.mark.parametrize('fault',['forged','missing','malformed'])
def test_resume_rebuilds_public_status_from_private_checkpoint(paths,fault):
    state=platform();plan=build_plan(paths,('chrome',),platform_state=state,env={})
    executor=Executor(paths,FakeCrypto(),lambda:state)
    result=executor.apply(plan,consent_id=plan.id,server_step_complete=True)
    report_path=paths.state/'runs'/plan.id/'result.json'
    if fault=='forged':
        result.update(full_reset=True,ready_for_new_account=True,network='verified',server='verified',
                      token='SENSITIVE_FORGED_REPORT_METADATA',chrome_profile_run='0'*32)
        report_path.write_text(json.dumps(result),encoding='utf-8')
    elif fault=='missing':report_path.unlink()
    else:report_path.write_text('{broken',encoding='utf-8')
    recovered=executor.resume(plan.id)
    assert recovered['full_reset'] is False and recovered['ready_for_new_account'] is False
    assert recovered['network']=='not_verified'
    assert recovered['server']=='user_reported_complete_not_independently_verified'
    assert recovered['chrome_profile_run']==plan.id
    assert 'token' not in recovered
    assert json.loads(report_path.read_text(encoding='utf-8'))==recovered
