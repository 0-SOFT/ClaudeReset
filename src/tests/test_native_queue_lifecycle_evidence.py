"""Packaged request lifecycle evidence must match the built source and fixture."""
import hashlib,json
import pytest
from test_native_runtime_trust_evidence import tool,ROOT

@pytest.mark.parametrize('fault',[None,'cases','negative','source','test','passed','installed','stubs','float'])
def test_lifecycle_evidence(tmp_path,fault):
    name='Sandboxie/core/svc/queueserver.cpp';source=tmp_path/'source'/name
    source.parent.mkdir(parents=True)
    source.write_text('// A premature fetch must not release the active worker identity.')
    digest=hashlib.sha256(source.read_bytes()).hexdigest()
    result=dict(cases=10,original_negative_controls=1,prepared_source_sha256=digest,
        test_sha256=hashlib.sha256((ROOT/'src/tests/native/QueueRequestLifecycleTests.cpp').read_bytes()).hexdigest(),
        passed=True,installed_service_test=False,api_stubs=True)
    fields={'cases':'cases','negative':'original_negative_controls','source':'prepared_source_sha256',
            'test':'test_sha256','passed':'passed','installed':'installed_service_test','stubs':'api_stubs'}
    if fault=='float':result['cases']=10.0
    elif fault:result.pop(fields[fault])
    path=tmp_path/'service/queue-request-lifecycle/result.json';path.parent.mkdir(parents=True)
    path.write_text(json.dumps(result))
    if fault:
        with pytest.raises(RuntimeError,match='Matching queue request lifecycle evidence'):tool.queue_lifecycle_evidence(tmp_path,{name:digest})
    else:assert tool.queue_lifecycle_evidence(tmp_path,{name:digest})==[path]
