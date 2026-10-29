"""Queue allocation failure proof must match the source packaged for review."""
import hashlib,json
import pytest
from test_native_runtime_trust_evidence import tool,ROOT

@pytest.mark.parametrize('fault',[None,'cases','negative','ids','ids-float','collision','collision-float','lifetime','lifetime-float','float','source','test','passed','installed','stubs','allocation'])
def test_queue_evidence(tmp_path,fault):
    name='Sandboxie/core/svc/queueserver.cpp';source=tmp_path/'source'/name
    source.parent.mkdir(parents=True);source.write_text('// queue takes ownership only after reply allocation')
    digest=hashlib.sha256(source.read_bytes()).hexdigest()
    result=dict(cases=4,original_negative_controls=4,process_lifetime_checks=4,request_id_boundary_checks=4,request_id_collision_checks=6,prepared_source_sha256=digest,
        test_sha256=hashlib.sha256((ROOT/'src/tests/native/QueueEventOwnershipTests.cpp').read_bytes()).hexdigest(),
        passed=True,installed_service_test=False,api_stubs=True,real_allocation_failure_injected=False)
    fields={'cases':'cases','negative':'original_negative_controls','ids':'request_id_boundary_checks','collision':'request_id_collision_checks','lifetime':'process_lifetime_checks','source':'prepared_source_sha256',
            'test':'test_sha256','passed':'passed','installed':'installed_service_test','stubs':'api_stubs',
            'allocation':'real_allocation_failure_injected'}
    if fault=='float':result['cases']=4.0
    elif fault=='ids-float':result['request_id_boundary_checks']=4.0
    elif fault=='lifetime-float':result['process_lifetime_checks']=4.0
    elif fault=='collision-float':result['request_id_collision_checks']=6.0
    elif fault:result.pop(fields[fault])
    path=tmp_path/'service/queue-event-ownership/result.json';path.parent.mkdir(parents=True)
    path.write_text(json.dumps(result))
    if fault:
        with pytest.raises(RuntimeError,match='Matching queue event ownership evidence'):tool.queue_event_evidence(tmp_path,{name:digest})
    else:assert tool.queue_event_evidence(tmp_path,{name:digest})==[path]
