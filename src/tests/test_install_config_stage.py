from contextlib import contextmanager
import json
import pytest
from claude_reset import backend_spec
from claude_reset.install_config_stage import _stage_configuration,ConfigurationReceipts
from claude_reset.install_stage import _stage_payload
from claude_reset.install_rollback import _rollback_installation_files
from claude_reset.install_store import Directory
from claude_reset.install_configuration import FILES
from claude_reset.safeio import SafetyError
from test_install_stage import fixture as payload_fixture
from test_backend_spec import inputs


@contextmanager
def fixture(tmp_path,monkeypatch,*,root_name='store',payload_bytes=None):
    with payload_fixture(tmp_path,monkeypatch,root_name=root_name,payload_bytes=payload_bytes) as (store,source,state):
        path=store.directories['root'].path/'Policy';path.mkdir()
        store.directories['Policy']=Directory(path)
        spec,data=inputs()
        for field,name in [('engine_sha256','Engine/engine.exe'),('runtime_sha256','Runtime/ClaudeResetRuntime.exe'),
                           ('gateway_sha256','Gateway/ClaudeResetGateway.exe')]:spec[field]=source.pins[name].sha256
        monkeypatch.setattr(backend_spec,'ENGINES',{'1.14.4':spec['engine_sha256']})
        yield store,source,state,json.dumps(spec).encode(),data


def test_stage_private_files_and_combined_rollback(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state,spec,data):
        with _stage_payload(store,source,'a'*32,lambda g:True):pass
        with _stage_configuration(store,source,'a'*32,spec,data,['C:\\'],lambda g:True) as staged:
            assert set(staged.pins)==set(FILES)
            assert staged.pins['Engine/engine.json'].data==data
            with pytest.raises(OSError):staged.pins['Engine/engine.json'].path.write_bytes(b'changed')
        assert len(ConfigurationReceipts(store.journal).load()['files'])==3
        state['state']='recovering';store.journal.save(state)
        result=_rollback_installation_files(store,'a'*32,lambda g:True)
        assert len(result['removed'])==26
        assert _rollback_installation_files(store,'a'*32,lambda g:True)['removed']==[]


@pytest.mark.parametrize('fault',['existing','boundary','generation','payload','intent','parent'])
def test_configuration_failure_before_writes(tmp_path,monkeypatch,fault):
    with fixture(tmp_path,monkeypatch) as (store,source,state,spec,data):
        root=store.directories['root'].path
        if fault=='existing':(root/'Policy/Sandboxie.ini').write_bytes(b'preserve')
        elif fault=='payload':
            value=json.loads(spec);value['runtime_sha256']='f'*64;spec=json.dumps(value).encode()
        elif fault=='intent':state['entries'][-1]['state']='done';store.journal.save(state)
        elif fault=='parent':store.directories['Policy'].close()
        before=sorted(str(p.relative_to(root)) for p in root.rglob('*'))
        with pytest.raises(SafetyError):
            _stage_configuration(store,source,'b'*32 if fault=='generation' else 'a'*32,
                                 spec,data,['C:\\'],lambda g:fault!='boundary')
        assert sorted(str(p.relative_to(root)) for p in root.rglob('*'))==before


def test_receipt_failure_after_creation_can_roll_back_recorded_file(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state,spec,data):
        def fail(self,pin):raise OSError('injected completion failure')
        monkeypatch.setattr(ConfigurationReceipts,'complete',fail)
        with pytest.raises(OSError):_stage_configuration(store,source,'a'*32,spec,data,['C:\\'],lambda g:True)
        rows=ConfigurationReceipts(store.journal).load()['files']
        assert len(rows)==1 and rows[0]['state']=='created'
        state['state']='recovering';store.journal.save(state)
        assert _rollback_installation_files(store,'a'*32,lambda g:True)['removed']==[FILES[0]]


def test_configuration_conflict_prevents_payload_deletion(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state,spec,data):
        with _stage_payload(store,source,'a'*32,lambda g:True):pass
        with _stage_configuration(store,source,'a'*32,spec,data,['C:\\'],lambda g:True):pass
        root=store.directories['root'].path
        path=root/'Policy/Sandboxie.ini';path.write_bytes(b'changed')
        state['state']='recovering';store.journal.save(state)
        with pytest.raises(SafetyError):_rollback_installation_files(store,'a'*32,lambda g:True)
        assert all((root/name).exists() for name in source.pins)
        assert path.read_bytes()==b'changed'


def test_boundary_lost_after_configuration_creation_preserves_empty_owned_file(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state,spec,data):
        calls=[]
        def closed(generation):
            assert generation=='a'*32;calls.append(generation)
            return len(calls)!=3
        with pytest.raises(SafetyError,match='before configuration write'):
            _stage_configuration(store,source,'a'*32,spec,data,['C:\\'],closed)
        rows=ConfigurationReceipts(store.journal).load()['files']
        assert len(rows)==1 and rows[0]['state']=='created' and rows[0]['identity']
        path=store.directories['root'].path/rows[0]['name']
        assert path.read_bytes()==b''
        state['state']='recovering';store.journal.save(state)
        assert _rollback_installation_files(store,'a'*32,lambda g:True)['removed']==[rows[0]['name']]
