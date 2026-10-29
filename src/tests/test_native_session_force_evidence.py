"""Do not package omitted refusal proof or an unguarded legacy launch switch."""
import hashlib
import json
import pytest
from test_native_runtime_trust_evidence import tool,ROOT


@pytest.mark.parametrize('fault',['setters','queries','children','mutation','option','float','session-source','start-source','session-test','start-test'])
def test_session_force_evidence_precedes_output(tmp_path,monkeypatch,fault):
    monkeypatch.syspath_prepend(str(ROOT/'tools'))
    combined=tmp_path/'combined';source=combined/'source';hashes={}
    session='Sandboxie/core/drv/session.c';start='Sandboxie/apps/start/start.cpp'
    for name,data in ((session,b'/* Managed policy has no runtime force-disable exceptions */'),
                      (start,b''),('Sandboxie/core/drv/conf.c',b''),('Sandboxie/core/drv/util.c',b'')):
        path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        hashes[name]=hashlib.sha256(data).hexdigest()
    (combined/'source-manifest.json').write_text(json.dumps(hashes),encoding='utf-8')
    (combined/'combined-receipt.json').write_text(json.dumps({'changes':{}}),encoding='utf-8')
    managed=combined/'managed-config';managed.mkdir()
    (managed/'manifest.json').write_text(json.dumps({'files':{session:{'prepared_sha256':hashes[session]}}}),encoding='utf-8')
    result=dict(managed_config_checks_passed=True,session_force_setters_checks=96,session_force_queries_checks=16,
        session_force_children_checks=4,session_force_mutation_checks=1,force_children_option_checks=4,
        session_force_source_sha256=hashes[session],force_disable_source_sha256=hashes[start],
        session_force_test_sha256=hashlib.sha256((ROOT/'src/tests/native/ManagedSessionForceTests.cpp').read_bytes()).hexdigest(),
        force_disable_test_sha256=hashlib.sha256((ROOT/'src/tests/native/ManagedDisableForceTests.cpp').read_bytes()).hexdigest())
    if fault in ('setters','queries','children','mutation'):result.pop('session_force_'+fault+'_checks')
    if fault=='option':result.pop('force_children_option_checks')
    if fault=='float':result['session_force_setters_checks']=96.0
    for f,k in [('session-source','session_force_source_sha256'),('start-source','force_disable_source_sha256'),
                ('session-test','session_force_test_sha256'),('start-test','force_disable_test_sha256')]:
        if fault==f:result[k]='0'*64
    (managed/'test-result.json').write_text(json.dumps(result),encoding='utf-8')
    output=tmp_path/'output'
    with pytest.raises(RuntimeError,match='Matching session force refusal evidence'):tool.main(combined,output)
    assert not output.exists()
