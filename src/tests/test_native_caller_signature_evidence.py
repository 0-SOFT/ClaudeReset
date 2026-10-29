"""Unsigned review packaging must retain proof that signer bypasses are absent."""
import hashlib
import json
import pytest
from test_native_runtime_trust_evidence import tool,ROOT


@pytest.mark.parametrize('fault',['missing-cases','wrong-cases','mismatch','invalid-accepted',
    'skipped','boolean-count','source','test'])
def test_packager_refuses_incomplete_caller_signature_proof(tmp_path,monkeypatch,fault):
    monkeypatch.syspath_prepend(str(ROOT/'tools'))
    combined=tmp_path/'combined';source=combined/'source';expected={}
    texts={'Sandboxie/core/drv/conf.c':'/* inert configuration */',
           'Sandboxie/core/drv/util.c':'/* Development certificates and OS test mode are not image authority */'}
    for name,text in texts.items():
        path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(text.encode())
        expected[name]=hashlib.sha256(path.read_bytes()).hexdigest()
    (combined/'source-manifest.json').write_text(json.dumps(expected),encoding='utf-8')
    (combined/'combined-receipt.json').write_text(json.dumps({'changes':{}}),encoding='utf-8')
    managed=combined/'managed-config';managed.mkdir()
    (managed/'manifest.json').write_text(json.dumps({'files':{name:{'prepared_sha256':h} for name,h in expected.items()}}),encoding='utf-8')
    tests=dict(managed_config_checks_passed=True,exact_service_identity_checks=39,
        caller_signature_checks=16,caller_signature_mismatches=0,caller_invalid_signature_accepted=0,
        caller_signature_checks_skipped=0,caller_signature_source_sha256=expected['Sandboxie/core/drv/util.c'],
        caller_signature_test_sha256=hashlib.sha256((ROOT/'src/tests/native/ManagedCallerSignatureTests.c').read_bytes()).hexdigest())
    if fault=='missing-cases':tests.pop('caller_signature_checks')
    if fault=='wrong-cases':tests['caller_signature_checks']=15
    if fault=='mismatch':tests['caller_signature_mismatches']=1
    if fault=='invalid-accepted':tests['caller_invalid_signature_accepted']=1
    if fault=='skipped':tests['caller_signature_checks_skipped']=1
    if fault=='boolean-count':tests['caller_signature_mismatches']=False
    if fault=='source':tests['caller_signature_source_sha256']='f'*64
    if fault=='test':tests['caller_signature_test_sha256']='f'*64
    (managed/'test-result.json').write_text(json.dumps(tests),encoding='utf-8')
    output=tmp_path/'candidate'
    with pytest.raises(RuntimeError,match='Matching caller signature enforcement evidence'):
        tool.main(combined,output)
    assert not output.exists()
