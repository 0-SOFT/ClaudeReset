"""A build cannot omit source-bound setter and preserved-query checks."""
import hashlib
import json
import pytest
from test_native_runtime_trust_evidence import tool,ROOT


@pytest.mark.parametrize('fault',['missing-setter','missing-query','float-count','source','test'])
def test_exemption_evidence_precedes_output(tmp_path,monkeypatch,fault):
    monkeypatch.syspath_prepend(str(ROOT/'tools'))
    combined=tmp_path/'combined';source=combined/'source'
    api='Sandboxie/core/drv/api.c';conf='Sandboxie/core/drv/conf.c';util='Sandboxie/core/drv/util.c'
    hashes={}
    for name,data in ((api,b'/* Managed process exemptions cannot override */'),(conf,b''),(util,b'')):
        path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        hashes[name]=hashlib.sha256(data).hexdigest()
    (combined/'source-manifest.json').write_text(json.dumps(hashes),encoding='utf-8')
    (combined/'combined-receipt.json').write_text(json.dumps({'changes':{}}),encoding='utf-8')
    managed=combined/'managed-config';managed.mkdir()
    (managed/'manifest.json').write_text(json.dumps({'files':{api:{'prepared_sha256':hashes[api]}}}),encoding='utf-8')
    result=dict(managed_config_checks_passed=True,service_port_authorization_checks=48,
        managed_exemption_setter_checks=48,managed_exemption_query_checks=48,
        exemption_source_sha256=hashes[api],
        exemption_test_sha256=hashlib.sha256((ROOT/'src/tests/native/ManagedExemptionTests.cpp').read_bytes()).hexdigest())
    if fault=='missing-setter':result.pop('managed_exemption_setter_checks')
    if fault=='missing-query':result.pop('managed_exemption_query_checks')
    if fault=='float-count':result['managed_exemption_query_checks']=48.0
    if fault=='source':result['exemption_source_sha256']='0'*64
    if fault=='test':result['exemption_test_sha256']='0'*64
    (managed/'test-result.json').write_text(json.dumps(result),encoding='utf-8')
    output=tmp_path/'output'
    with pytest.raises(RuntimeError,match='Matching process exemption evidence'):tool.main(combined,output)
    assert not output.exists()
