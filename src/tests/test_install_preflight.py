import hashlib
import json
import pytest
from claude_reset.backend import preflight as p
from claude_reset.safeio import SafetyError
from test_install_payload import fixture
from scripted import Strict


@pytest.mark.parametrize('fault',[None,'catalog','signature','inventory','occupied'])
def test_preflight_keeps_all_files_pinned_and_never_authorizes_installation(tmp_path,monkeypatch,fault):
    digest=fixture(tmp_path,monkeypatch);cat=tmp_path/'release.cat';cat.write_bytes(b'inert catalog')
    cat_digest=hashlib.sha256(cat.read_bytes()).hexdigest();calls=[]
    def catalog(pin,payload):
        assert pin.handle and payload.report()['payload_files']==23
        with pytest.raises(OSError):cat.write_bytes(b'replaced')
        if fault=='catalog':raise SafetyError('unsigned catalog')
        return dict(catalog_authenticode_verified=True,manifest_membership_verified=True,release_authority_verified=False)
    def signature(pin):
        assert pin.handle;calls.append(pin.path)
        with pytest.raises(OSError):pin.path.write_bytes(b'replaced')
        if fault=='signature':raise SafetyError('unsigned payload')
        return dict(authenticode_verified=True,release_authority_verified=False)
    def inventory():
        if fault=='inventory':raise SafetyError('query refused')
        return dict(fresh_install_blockers=[dict(code='service_slot_occupied')] if fault=='occupied' else [])
    evidence=Strict(release_catalog=catalog,signature=signature,slots=inventory)
    result=p.inspect_candidate(tmp_path,digest,cat,cat_digest,evidence=evidence)
    assert calls and result['payload_integrity_verified']
    assert result['status']=='candidate_preflight_blocked' and result['passed'] is False
    assert all(result[name] is False for name in ('installable','client_admission','settings_changed','release_authority_verified','kernel_load_verified'))
    assert 'approved_release_authority_missing' in result['blockers']
    if fault is None:assert len(result['blockers'])==2
    else:assert len(result['blockers'])==3
    # Closing the inspection releases immutable pins but never deletes files.
    cat.write_bytes(b'released');calls[0].write_bytes(b'released')


def test_invalid_payload_never_reaches_signature_or_system_inventory(tmp_path,monkeypatch,capsys):
    fixture(tmp_path,monkeypatch)
    result=p.main(['--bundle',str(tmp_path),'--expected-manifest-sha256','0'*64,
                   '--catalog',str(tmp_path/'missing.cat'),'--expected-catalog-sha256','a'*64],
                  evidence=Strict())   # an invalid package is refused before any evidence is read
    value=json.loads(capsys.readouterr().out)
    assert result==1 and value['status']=='candidate_preflight_failed' and not value['client_admission']


def test_cli_has_no_install_or_elevation_option():
    with pytest.raises(SystemExit) as error:p.main(['--install'])
    assert error.value.code==2


def test_preflight_does_not_export_foreign_service_command_or_account(tmp_path,monkeypatch,capsys):
    digest=fixture(tmp_path,monkeypatch);cat=tmp_path/'release.cat';cat.write_bytes(b'inert catalog')
    cat_digest=hashlib.sha256(cat.read_bytes()).hexdigest()
    inventory=dict(schema=2,root='C:\\SECRET-user\\ClaudeReset',root_occupied=True,
                   services=[dict(name='SbieSvc',exists=True,state=1,pid=0,start=3,type=16,
                                  binary='C:\\foreign.exe --token SECRET-token',account='SECRET-account',
                                  future_private_field='SECRET-future')],registry_slots=[],
                   fresh_install_blockers=[dict(code='service_slot_occupied',service='SbieSvc')],
                   future_private_field='SECRET-future')
    before=json.dumps(inventory,sort_keys=True)
    evidence=Strict(release_catalog=dict(catalog_authenticode_verified=True),
                    signature=dict(authenticode_verified=True),slots=lambda:inventory)
    status=p.main(['--bundle',str(tmp_path),'--expected-manifest-sha256',digest,
                  '--catalog',str(cat),'--expected-catalog-sha256',cat_digest],evidence=evidence)
    output=capsys.readouterr();assert status==2 and not output.err and 'SECRET' not in output.out
    report=json.loads(output.out)
    assert report['installation_inventory']['services']==[
        dict(name='SbieSvc',exists=True,state=1,pid=0,start=3,type=16)]
    assert report['installation_inventory']['root_occupied'] is True
    assert 'installation_slots_occupied' in report['blockers'] and report['client_admission'] is False
    assert json.dumps(inventory,sort_keys=True)==before
