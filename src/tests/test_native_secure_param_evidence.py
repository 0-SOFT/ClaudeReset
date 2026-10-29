"""The secure-parameter setter requires source-bound role and startup evidence."""
import hashlib
import json
import pytest
from test_native_runtime_trust_evidence import tool,ROOT


@pytest.mark.parametrize('fault',['role','startup','float','source','test'])
def test_secure_param_proof_precedes_packaging(tmp_path,monkeypatch,fault):
    monkeypatch.syspath_prepend(str(ROOT/'tools'))
    combined=tmp_path/'combined';source=combined/'source';api='Sandboxie/core/drv/api.c';hashes={}
    for name,data in ((api,b'/* Secure parameter writes belong to the exact SYSTEM service image */'),
                      ('Sandboxie/core/drv/conf.c',b''),('Sandboxie/core/drv/util.c',b'')):
        path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        hashes[name]=hashlib.sha256(data).hexdigest()
    (combined/'source-manifest.json').write_text(json.dumps(hashes),encoding='utf-8')
    (combined/'combined-receipt.json').write_text(json.dumps({'changes':{}}),encoding='utf-8')
    managed=combined/'managed-config';managed.mkdir()
    (managed/'manifest.json').write_text(json.dumps({'files':{api:{'prepared_sha256':hashes[api]}}}),encoding='utf-8')
    result=dict(managed_config_checks_passed=True,service_port_authorization_checks=48,
        secure_param_role_checks=64,secure_param_startup_checks=4,secure_param_source_sha256=hashes[api],
        secure_param_test_sha256=hashlib.sha256((ROOT/'src/tests/native/ManagedSecureParamTests.cpp').read_bytes()).hexdigest())
    if fault in ('role','startup'):result.pop('secure_param_'+fault+'_checks')
    if fault=='float':result['secure_param_role_checks']=64.0
    if fault=='source':result['secure_param_source_sha256']='0'*64
    if fault=='test':result['secure_param_test_sha256']='0'*64
    (managed/'test-result.json').write_text(json.dumps(result),encoding='utf-8')
    output=tmp_path/'output'
    with pytest.raises(RuntimeError,match='Matching secure-parameter role evidence'):tool.main(combined,output)
    assert not output.exists()
