"""Packaging must retain source-bound proof of both force-disable refusal paths."""
import hashlib
import json
import pytest
from test_native_runtime_trust_evidence import tool,ROOT


@pytest.mark.parametrize('fault',['command','launch','float','source','test'])
def test_force_disable_proof_is_required_before_packaging(tmp_path,monkeypatch,fault):
    monkeypatch.syspath_prepend(str(ROOT/'tools'))
    combined=tmp_path/'combined';source=combined/'source'
    start='Sandboxie/apps/start/start.cpp';hashes={}
    for name,data in ((start,b'/* Force-disable refusal must stop before Program_Start */'),
                      ('Sandboxie/core/drv/conf.c',b''),('Sandboxie/core/drv/util.c',b'')):
        path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        hashes[name]=hashlib.sha256(data).hexdigest()
    (combined/'source-manifest.json').write_text(json.dumps(hashes),encoding='utf-8')
    (combined/'combined-receipt.json').write_text(json.dumps({'changes':{}}),encoding='utf-8')
    managed=combined/'managed-config';managed.mkdir()
    (managed/'manifest.json').write_text(json.dumps({'files':{start:{'prepared_sha256':hashes[start]}}}),encoding='utf-8')
    result=dict(managed_config_checks_passed=True,force_disable_command_checks=10,force_disable_launch_checks=10,
        force_disable_source_sha256=hashes[start],
        force_disable_test_sha256=hashlib.sha256((ROOT/'src/tests/native/ManagedDisableForceTests.cpp').read_bytes()).hexdigest())
    if fault in ('command','launch'):result.pop('force_disable_'+fault+'_checks')
    if fault=='float':result['force_disable_launch_checks']=10.0
    if fault=='source':result['force_disable_source_sha256']='0'*64
    if fault=='test':result['force_disable_test_sha256']='0'*64
    (managed/'test-result.json').write_text(json.dumps(result),encoding='utf-8')
    output=tmp_path/'output'
    with pytest.raises(RuntimeError,match='Matching force-disable status evidence'):tool.main(combined,output)
    assert not output.exists()
