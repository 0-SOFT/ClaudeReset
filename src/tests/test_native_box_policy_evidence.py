"""Reject missing or stale proof of the installer's per-box isolation contract."""
import hashlib
import json
import pytest
from test_native_runtime_trust_evidence import tool,ROOT


def test_native_contract_matches_the_installer_sources(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT/'tools'))
    from prepare_managed_config import managed_policy_contract,managed_forbidden_settings
    from claude_reset.broker_policy import ISOLATION_SETTINGS,FORBIDDEN_SETTINGS
    from claude_reset.install_configuration import BOXES
    boxes,settings=managed_policy_contract()
    assert boxes==BOXES and dict(settings)==ISOLATION_SETTINGS
    assert managed_forbidden_settings()==FORBIDDEN_SETTINGS


@pytest.mark.parametrize('fault',['foreign-module','duplicate-box','case-alias-box','case-alias-setting','unsafe-name','nonboolean-value'])
def test_unreviewed_contract_refuses_native_generation(tmp_path,monkeypatch,fault):
    monkeypatch.syspath_prepend(str(ROOT/'tools'))
    from prepare_managed_config import managed_policy_contract
    from claude_reset import broker_policy,install_configuration
    if fault=='foreign-module':monkeypatch.setattr(broker_policy,'__file__',str(tmp_path/'foreign.py'))
    if fault=='duplicate-box':monkeypatch.setattr(install_configuration,'BOXES',('ClaudeReset.Code',)*5)
    if fault=='case-alias-box':monkeypatch.setattr(install_configuration,'BOXES',('ClaudeReset.Code','ClaudeReset.code',*install_configuration.BOXES[2:]))
    if fault=='case-alias-setting':monkeypatch.setattr(broker_policy,'ISOLATION_SETTINGS',{'Strict':'y','strict':'y'})
    if fault=='unsafe-name':monkeypatch.setattr(broker_policy,'ISOLATION_SETTINGS',{'quote"':'y'})
    if fault=='nonboolean-value':monkeypatch.setattr(broker_policy,'ISOLATION_SETTINGS',{'ClaudeResetStrictBroker':'yes'})
    with pytest.raises(RuntimeError):managed_policy_contract()


def test_serialized_installer_ini_contains_every_native_required_value_once(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT/'tools'))
    from prepare_managed_config import managed_policy_contract
    from claude_reset.install_configuration import compile_configuration
    from test_install_configuration import fixture
    spec,data,payload=fixture()
    raw=dict(compile_configuration(json.dumps(spec).encode(),data,payload,['C:\\','D:\\']).files())['Policy/Sandboxie.ini']
    sections={};current=None
    for line in raw.decode('utf-16').splitlines():
        if not line:continue
        if line.startswith('['):
            current={};sections[line[1:-1]]=current
        else:
            key,value=line.split('=',1);current.setdefault(key.casefold(),[]).append(value)
    boxes,settings=managed_policy_contract()
    assert set(sections)=={'GlobalSettings',*boxes}
    for box in boxes:
        for name,value in settings:assert sections[box][name.casefold()]==[value]


@pytest.mark.parametrize('fault',['missing-count','wrong-count','float-count','contract','missing-contract','test',
                                'missing-forbidden','wrong-forbidden','float-forbidden','forbidden-contract'])
def test_box_policy_evidence_is_required_before_packaging(tmp_path,monkeypatch,fault):
    monkeypatch.syspath_prepend(str(ROOT/'tools'))
    from prepare_managed_config import managed_policy_contract,managed_forbidden_settings
    boxes,settings=managed_policy_contract()
    forbidden=managed_forbidden_settings()
    combined=tmp_path/'combined';source=combined/'source';name='Sandboxie/core/drv/conf.c'
    path=source/name;path.parent.mkdir(parents=True);path.write_bytes(b'/* Every fixed managed box */')
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    (combined/'source-manifest.json').write_text(json.dumps({name:digest}),encoding='utf-8')
    (combined/'combined-receipt.json').write_text(json.dumps({'changes':{}}),encoding='utf-8')
    managed=combined/'managed-config';managed.mkdir()
    (managed/'manifest.json').write_text(json.dumps({'files':{name:{'prepared_sha256':digest}}}),encoding='utf-8')
    tests=dict(managed_config_checks_passed=True,managed_box_policy_checks=len(boxes)*(4+6*len(settings)),
        managed_forbidden_setting_checks=(len(boxes)+1)*len(forbidden)*12,
        managed_forbidden_contract_sha256=hashlib.sha256(json.dumps(forbidden,separators=(',',':')).encode()).hexdigest(),
        managed_policy_contract_sha256=hashlib.sha256(json.dumps((boxes,settings),separators=(',',':')).encode()).hexdigest(),
        managed_policy_test_sha256=hashlib.sha256((ROOT/'src/tests/native/ManagedPolicyTests.c').read_bytes()).hexdigest())
    if fault=='missing-count':tests.pop('managed_box_policy_checks')
    if fault=='wrong-count':tests['managed_box_policy_checks']-=1
    if fault=='float-count':tests['managed_box_policy_checks']=float(tests['managed_box_policy_checks'])
    if fault=='contract':tests['managed_policy_contract_sha256']='f'*64
    if fault=='missing-contract':tests.pop('managed_policy_contract_sha256')
    if fault=='test':tests['managed_policy_test_sha256']='f'*64
    if fault=='missing-forbidden':tests.pop('managed_forbidden_setting_checks')
    if fault=='wrong-forbidden':tests['managed_forbidden_setting_checks']-=1
    if fault=='float-forbidden':tests['managed_forbidden_setting_checks']=float(tests['managed_forbidden_setting_checks'])
    if fault=='forbidden-contract':tests['managed_forbidden_contract_sha256']='f'*64
    (managed/'test-result.json').write_text(json.dumps(tests),encoding='utf-8')
    output=tmp_path/'candidate'
    with pytest.raises(RuntimeError,match='Matching managed box policy evidence'):tool.main(combined,output)
    assert not output.exists()
