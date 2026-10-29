from copy import deepcopy
from pathlib import Path
import pytest
from claude_reset import install_ownership as o
from claude_reset.install_payload import FILES,ENGINES
from claude_reset.safeio import SafetyError

ROOT=Path('C:/Program Files/ClaudeReset')


def inputs():
    value={'schema':1,'product':'ClaudeReset','generation':'a'*32,'version':'0.4.2','package_sha256':'b'*64,
           'files':{name:{'sha256':'c'*64,'bytes':7} for name in FILES}}
    value['files']['Engine/engine.exe']['sha256']=next(iter(ENGINES.values()))
    rows=[{'name':name,'exists':True,'state':1,'pid':0,**{k:v for k,v in row.items() if k!='image'}}
          for name,row in o.configurations(ROOT).items()]
    hashes={name:row['sha256'] for name,row in value['files'].items()}
    return value,rows,hashes


def test_exact_fields_are_only_a_comparison_not_mutation_authority():
    result=o.assess(*inputs(),ROOT)
    assert result['ownership_fields_match'] and not result['may_mutate']
    assert not result['driver_unload_authorized'] and not result['client_admission']
    assert result['busy_services']==[]


@pytest.mark.parametrize('index',range(4))
@pytest.mark.parametrize('pid',[123,None,False,'0',-1])
def test_stopped_status_requires_a_verified_zero_process_id(index,pid):
    record,rows,hashes=inputs();rows[index]['pid']=pid
    result=o.assess(record,rows,hashes,ROOT)
    assert result['busy_services']==[o.SERVICES[index]]
    assert result['ownership_fields_match'] and not result['may_mutate']
    assert not result['driver_unload_authorized'] and not result['client_admission']


def test_missing_pid_is_not_assumed_stopped():
    record,rows,hashes=inputs();rows[0].pop('pid')
    assert o.assess(record,rows,hashes,ROOT)['busy_services']==['ClaudeResetBackend']


@pytest.mark.parametrize('field,value',[
    ('binary','"C:\\elsewhere.exe"'),('account','LocalService'),('type',32),('start',2),('type',True)])
def test_same_service_name_does_not_adopt_changed_registration(field,value):
    record,rows,hashes=inputs();rows[0][field]=value
    assert not o.assess(record,rows,hashes,ROOT)['ownership_fields_match']


def test_missing_changed_or_extra_files_are_not_owned():
    record,rows,hashes=inputs();hashes.pop('Engine/engine.exe');hashes['unexpected.exe']='d'*64
    hashes['Runtime/ClaudeResetRuntime.exe']='e'*64
    result=o.assess(record,rows,hashes,ROOT)
    assert len(result['mismatches'])==3 and not result['may_mutate']


def test_running_driver_is_not_unloaded_even_when_all_hashes_match():
    record,rows,hashes=inputs();rows[-1]['state']=4
    result=o.assess(record,rows,hashes,ROOT)
    assert result['busy_services']==['SbieDrv'] and result['ownership_fields_match']
    assert not result['driver_unload_authorized']


@pytest.mark.parametrize('change',[{'schema':True},{'product':'Other'},{'generation':'../other'},
    {'version':'1.0.0 --command'},{'root':'C:\\elsewhere'},{'files':{}},{'package_sha256':[]}])
def test_record_cannot_select_commands_or_paths(change):
    value,_,_=inputs()
    with pytest.raises(SafetyError):o.record({**value,**change})


def test_missing_inventory_rows_are_not_assumed_absent():
    record,rows,hashes=inputs()
    with pytest.raises(SafetyError):o.assess(record,rows[:-1],hashes,ROOT)
