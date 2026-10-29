"""Reject missing, stale and overclaimed queue reply ownership evidence."""
import hashlib,json
import pytest
from test_native_runtime_trust_evidence import tool,ROOT

@pytest.mark.parametrize('fault',[None,'missing','cases','negative','float','source','test','passed','installed','stubs'])
def test_queue_reply_evidence(tmp_path,fault):
    name='Sandboxie/core/svc/queueserver.cpp';source=tmp_path/'source'/name
    source.parent.mkdir(parents=True);source.write_text('// Preserve the first reply until the client consumes it.')
    digest=hashlib.sha256(source.read_bytes()).hexdigest()
    result=dict(cases=6,original_negative_controls=1,prepared_source_sha256=digest,
        test_sha256=hashlib.sha256((ROOT/'src/tests/native/QueueReplyOwnershipTests.cpp').read_bytes()).hexdigest(),
        passed=True,installed_service_test=False,api_stubs=True)
    fields={'cases':'cases','negative':'original_negative_controls','source':'prepared_source_sha256',
            'test':'test_sha256','passed':'passed','installed':'installed_service_test','stubs':'api_stubs'}
    if fault=='float':result['cases']=6.0
    elif fault in fields:result.pop(fields[fault])
    path=tmp_path/'service/queue-reply-ownership/result.json';path.parent.mkdir(parents=True)
    if fault!='missing':path.write_text(json.dumps(result))
    if fault=='missing':
        with pytest.raises(FileNotFoundError):tool.queue_reply_evidence(tmp_path,{name:digest})
    elif fault:
        with pytest.raises(RuntimeError,match='Matching queue reply ownership evidence'):tool.queue_reply_evidence(tmp_path,{name:digest})
    else:assert tool.queue_reply_evidence(tmp_path,{name:digest})==[path]
