import os
import pytest
from claude_reset.install_store import Directory, _create_child, validate_parent, TRUSTED_INSTALLER
from claude_reset.safeio import SafetyError
from claude_reset.windows import ps_json
from claude_reset.netguard import psq

pytestmark=pytest.mark.skipif(os.name!='nt',reason='Windows directory handles and creation ACL')


@pytest.fixture(scope='module')
def user_sid():
    return ps_json('[Security.Principal.WindowsIdentity]::GetCurrent().User.Value | ConvertTo-Json -Compress')


def test_new_directory_has_protected_acl_at_creation_and_does_not_inherit(tmp_path,user_sid):
    with Directory(tmp_path) as parent:
        with _create_child(parent,'private','D:P(A;OICI;FA;;;'+user_sid+')') as child:
            sample=child.path/'payload';sample.write_bytes(b'fixture')
            value=ps_json('$a=Get-Acl -LiteralPath '+psq(str(child.path))+
                ';$b=Get-Acl -LiteralPath '+psq(str(sample))+
                ';@{protected=$a.AreAccessRulesProtected;directory_sids=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {$_.IdentityReference.Value});file_sids=@($b.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {$_.IdentityReference.Value})}|ConvertTo-Json -Compress')
            assert value=={'protected':True,'directory_sids':[user_sid],'file_sids':[user_sid]}
            with pytest.raises(OSError):child.path.rename(tmp_path/'replacement')
        (tmp_path/'private').rename(tmp_path/'released')


def test_existing_directory_is_never_adopted_or_repaired(tmp_path,user_sid):
    existing=tmp_path/'private';existing.mkdir();sentinel=existing/'unrelated'
    sentinel.write_bytes(b'preserve')
    with Directory(tmp_path) as parent:
        with pytest.raises(SafetyError,match='adoption'):
            _create_child(parent,'private','D:P(A;OICI;FA;;;'+user_sid+')')
    assert sentinel.read_bytes()==b'preserve'


@pytest.mark.parametrize('name',['../outside','C:drive','CON','LPT1.txt','trailing.','a/b','a\\b',''])
def test_directory_component_cannot_escape_or_alias(tmp_path,user_sid,name):
    with Directory(tmp_path) as parent:
        with pytest.raises(SafetyError):_create_child(parent,name,'D:P(A;;FA;;;'+user_sid+')')
    assert list(tmp_path.iterdir())==[]


def test_regular_file_is_rejected_and_handle_released(tmp_path):
    path=tmp_path/'file';path.write_bytes(b'fixture')
    with pytest.raises(SafetyError):Directory(path)
    path.rename(tmp_path/'released')


def test_closed_parent_cannot_create_child(tmp_path):
    parent=Directory(tmp_path);parent.close()
    with pytest.raises(SafetyError):_create_child(parent,'child','D:P(A;;FA;;;SY)')
    assert list(tmp_path.iterdir())==[]


def parent_acl():
    return {'owner':TRUSTED_INSTALLER,'reparse':False,
            'rules':[{'sid':s,'rights':0x1f01ff,'type':'Allow'}
                     for s in (TRUSTED_INSTALLER,'S-1-5-18','S-1-5-32-544')]}


def test_windows_servicing_authority_is_allowed_on_parent_only():
    validate_parent(parent_acl())
    from claude_reset.service_store import validate_acl
    with pytest.raises(SafetyError):validate_acl(parent_acl())


def test_user_writable_parent_prevents_bootstrap():
    value=parent_acl();value['rules'].append({'sid':'S-1-5-11','rights':2,'type':'Allow'})
    with pytest.raises(SafetyError):validate_parent(value)


def test_parent_without_system_control_is_rejected():
    value=parent_acl();value['rules']=[r for r in value['rules'] if r['sid']!='S-1-5-18']
    with pytest.raises(SafetyError):validate_parent(value)


@pytest.fixture
def bootstrap_fixture(tmp_path,monkeypatch,user_sid):
    """Own-directory bootstrap; production elevation/ACL authority is not claimed."""
    from claude_reset import install_store as module
    from claude_reset import install_scm as scm
    from claude_reset.install_inventory import SERVICES
    monkeypatch.setattr(module,'_require_admin',lambda:None)
    monkeypatch.setattr(module,'program_files',lambda:tmp_path)
    monkeypatch.setattr(module,'_verify_parent',lambda parent:None)
    monkeypatch.setattr(module,'services',lambda:[{'name':name,'exists':False} for name in SERVICES])
    monkeypatch.setattr(scm,'require_vacant_registry_slot',lambda name:None)
    descriptor='D:P(A;OICI;FA;;;'+user_sid+')'
    for name in ('PRIVATE','ROOT_ACL','RUNTIME_READ'):monkeypatch.setattr(module,name,descriptor)
    def inspect(paths,directories):
        # Exercise the real creation ACL, with the test owner's SID instead of
        # claiming an administrative Program Files installation.
        values=','.join(psq(str(p)) for p in paths)
        facts=ps_json('@{rows=@('+values+'|ForEach-Object {$a=Get-Acl -LiteralPath $_;@{protected=$a.AreAccessRulesProtected;owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value}})}|ConvertTo-Json -Depth 4 -Compress')
        assert len(facts['rows'])==len(paths)
        assert all(r['owner']==user_sid for r in facts['rows'])
        if directories:assert all(r['protected'] for r in facts['rows'])
    monkeypatch.setattr(module,'verify_paths',inspect)
    return module


def test_bootstrap_records_generation_and_holds_all_directories(tmp_path,bootstrap_fixture):
    module=bootstrap_fixture
    with module.create_store('a'*32,'b'*64) as store:
        value=store.journal.load()
        assert value['generation']=='a'*32 and value['package_sha256']=='b'*64
        assert value['entries']==[] and not value['client_admission']
        assert set(store.directories)=={'root','parent',*module.FOLDERS}
        with pytest.raises(OSError):(tmp_path/'ClaudeReset').rename(tmp_path/'other')
    (tmp_path/'ClaudeReset').rename(tmp_path/'released')


def test_bootstrap_collision_creates_nothing(tmp_path,bootstrap_fixture,monkeypatch):
    module=bootstrap_fixture
    from claude_reset.install_inventory import SERVICES
    monkeypatch.setattr(module,'services',lambda:[{'name':name,'exists':name=='SbieDrv'} for name in SERVICES])
    with pytest.raises(SafetyError,match='Occupied'):module.create_store('a'*32,'b'*64)
    assert list(tmp_path.iterdir())==[]


def test_bootstrap_does_not_adopt_an_existing_root(tmp_path,bootstrap_fixture):
    root=tmp_path/'ClaudeReset';root.mkdir();(root/'sentinel').write_bytes(b'other owner')
    with pytest.raises(SafetyError,match='Occupied'):bootstrap_fixture.create_store('a'*32,'b'*64)
    assert list(root.iterdir())==[root/'sentinel']


def test_bootstrap_partial_failure_keeps_journal_and_releases_handles(tmp_path,bootstrap_fixture,monkeypatch):
    module=bootstrap_fixture;real=module._create_child
    def fail(parent,name,sddl):
        if name=='Engine':raise OSError('injected directory creation failure')
        return real(parent,name,sddl)
    monkeypatch.setattr(module,'_create_child',fail)
    with pytest.raises(OSError):module.create_store('a'*32,'b'*64)
    import json
    root=tmp_path/'ClaudeReset'
    record=json.loads((root/'Installer/install-journal.json').read_text())
    assert record['generation']=='a'*32 and record['entries']==[]
    assert (root/'Backend').is_dir() and not (root/'Engine').exists()
    root.rename(tmp_path/'released')


def incomplete_bootstrap(module,monkeypatch):
    real=module._create_child
    def fail(parent,name,sddl):
        if name=='Engine':raise OSError('injected failure')
        return real(parent,name,sddl)
    with monkeypatch.context() as patch:
        patch.setattr(module,'_create_child',fail)
        with pytest.raises(OSError):module.create_store('a'*32,'b'*64)
    return real


def test_recorded_bootstrap_recovers_and_is_repeatable(tmp_path,bootstrap_fixture,monkeypatch):
    from claude_reset.install_bootstrap import recover_bootstrap,DirectoryReceipts
    module=bootstrap_fixture
    incomplete_bootstrap(module,monkeypatch)
    with recover_bootstrap('a'*32,'b'*64) as recovered:
        rows=DirectoryReceipts(recovered.journal).load()['directories']
        assert len(rows)==len(module.FOLDERS)+1
        assert recovered.journal.load()['entries']==[]
        assert not recovered.journal.load()['client_admission']
    with recover_bootstrap('a'*32,'b'*64) as recovered:
        assert DirectoryReceipts(recovered.journal).load()['directories']==rows


@pytest.mark.parametrize('fault',['replacement','unrecorded','extra','generation','journal','missing_receipt','service'])
def test_bootstrap_recovery_refuses_conflicts_before_creation(tmp_path,bootstrap_fixture,monkeypatch,fault):
    from claude_reset.install_bootstrap import recover_bootstrap
    from claude_reset.install_inventory import SERVICES
    module=bootstrap_fixture
    incomplete_bootstrap(module,monkeypatch)
    root=tmp_path/'ClaudeReset'
    if fault=='replacement':
        (root/'Backend').rename(tmp_path/'original-backend')
        (root/'Backend').mkdir()
    elif fault=='unrecorded':(root/'Engine').mkdir()
    elif fault=='extra':(root/'Backend/keep.txt').write_bytes(b'preserve')
    elif fault=='journal':
        import json
        path=root/'Installer/install-journal.json'
        value=json.loads(path.read_text());value['entries']=[{'step':'inventory_backup','state':'intent'}]
        path.write_text(json.dumps(value))
    elif fault=='missing_receipt':(root/'Installer/directory-receipts.json').unlink()
    elif fault=='service':
        monkeypatch.setattr(module,'services',lambda:[{'name':name,'exists':name=='SbieDrv'} for name in SERVICES])
    before=sorted(str(p.relative_to(root)) for p in root.rglob('*'))
    with pytest.raises((SafetyError,OSError)):
        recover_bootstrap('c'*32 if fault=='generation' else 'a'*32,'b'*64)
    assert sorted(str(p.relative_to(root)) for p in root.rglob('*'))==before
    root.rename(tmp_path/'released')


def test_bootstrap_unrecorded_creation_is_preserved(tmp_path,bootstrap_fixture,monkeypatch):
    from claude_reset.install_bootstrap import recover_bootstrap,DirectoryReceipts
    module=bootstrap_fixture
    with monkeypatch.context() as patch:
        patch.setattr(DirectoryReceipts,'record',lambda *args:(_ for _ in ()).throw(OSError('receipt write failure')))
        with pytest.raises(OSError):module.create_store('a'*32,'b'*64)
    with pytest.raises(SafetyError,match='Unrecorded'):recover_bootstrap('a'*32,'b'*64)
    assert (tmp_path/'ClaudeReset/Backend').is_dir()


@pytest.mark.parametrize('recovery',[False,True])
@pytest.mark.parametrize('slot',['ClaudeResetBackend','ClaudeResetGateway','SbieSvc','SbieDrv'])
def test_orphan_registry_slot_blocks_directory_creation(tmp_path,bootstrap_fixture,monkeypatch,recovery,slot):
    from claude_reset import install_scm as scm
    from claude_reset.install_bootstrap import recover_bootstrap
    module=bootstrap_fixture
    if recovery:incomplete_bootstrap(module,monkeypatch)
    before=sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob('*'));calls=[]
    def registry(name):
        calls.append(name)
        if name==slot:raise SafetyError('Registry slot occupied or inaccessible')
    monkeypatch.setattr(scm,'require_vacant_registry_slot',registry)
    with pytest.raises(SafetyError,match='Registry slot'):
        (recover_bootstrap if recovery else module.create_store)('a'*32,'b'*64)
    assert slot in calls and sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob('*'))==before


@pytest.mark.parametrize('recovery',[False,True])
def test_new_registry_collision_between_directories_stops_further_creation(tmp_path,bootstrap_fixture,monkeypatch,recovery):
    from claude_reset import install_scm as scm
    from claude_reset.install_bootstrap import recover_bootstrap
    module=bootstrap_fixture
    if recovery:incomplete_bootstrap(module,monkeypatch)
    real=module._create_child;created=[]
    def create(parent,name,sddl):
        result=real(parent,name,sddl);created.append(name);return result
    monkeypatch.setattr(module,'_create_child',create)
    def registry(name):
        if created:raise SafetyError('New registry collision')
    monkeypatch.setattr(scm,'require_vacant_registry_slot',registry)
    with pytest.raises(SafetyError,match='New registry collision'):
        (recover_bootstrap if recovery else module.create_store)('a'*32,'b'*64)
    assert created==(['Engine'] if recovery else ['ClaudeReset'])
    assert not (tmp_path/'ClaudeReset/Gateway').exists()
