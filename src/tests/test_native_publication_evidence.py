"""Packaging must reject incomplete or stale publication proof before building output."""
import hashlib
import json
from pathlib import Path
import pytest
from test_native_runtime_trust_evidence import tool, ROOT


@pytest.mark.parametrize('fault',['wfp-lost','object-lost','waiting-wfp-lost','waiting-object-lost',
    'startup','ready','wrong-source','wrong-test','integer-success'])
def test_packager_refuses_unbound_publication_evidence(tmp_path,monkeypatch,fault):
    monkeypatch.syspath_prepend(str(ROOT/'tools'))
    combined=tmp_path/'combined';source=combined/'source'
    name='Sandboxie/core/drv/conf.c';path=source/name;path.parent.mkdir(parents=True)
    path.write_bytes(b'BOOLEAN require_ready; /* inert packaging fixture */')
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    (combined/'source-manifest.json').write_text(json.dumps({name:digest}),encoding='utf-8')
    (combined/'combined-receipt.json').write_text(json.dumps({'changes':{}}),encoding='utf-8')
    managed=combined/'managed-config';managed.mkdir()
    (managed/'manifest.json').write_text(json.dumps({'files':{name:{'prepared_sha256':digest}}}),encoding='utf-8')
    tests={'managed_config_checks_passed':True,'publication_source_sha256':digest,
        'publication_test_sha256':hashlib.sha256((ROOT/'src/tests/native/ManagedPublicationTests.c').read_bytes()).hexdigest()}
    for mode in ('wfp-lost','object-lost','waiting-wfp-lost','waiting-object-lost','startup','ready'):
        tests['publication_'+mode+'_passed']=True
    if fault=='wrong-source':tests['publication_source_sha256']='a'*64
    elif fault=='wrong-test':tests['publication_test_sha256']='a'*64
    elif fault=='integer-success':tests['publication_ready_passed']=1
    else:tests.pop('publication_'+fault+'_passed')
    (managed/'test-result.json').write_text(json.dumps(tests),encoding='utf-8')
    output=tmp_path/'candidate'
    with pytest.raises(RuntimeError,match='Matching configuration publication evidence'):
        tool.main(combined,output)
    assert not output.exists()
