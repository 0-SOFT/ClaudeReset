"""Reject missing, stale or inflated broker classification proof at packaging."""
import hashlib,json
import pytest
from test_native_runtime_trust_evidence import tool,ROOT

@pytest.mark.parametrize('fault',[None,'service_cases','driver_cases','negative_controls','float','source','test',
    'installed','production_clients_permitted','loaded_driver_verified'])
def test_classifier_evidence(tmp_path,fault):
    names=('Sandboxie/core/svc/CrBrokerWindows.h','Sandboxie/core/drv/CrBrokerQuery.h','Sandboxie/core/drv/process_api.c')
    expected={n:str(i)*64 for i,n in enumerate(names)}
    result=dict(service_cases=90,driver_cases=72,negative_controls=3,source_sha256=expected,
        test_sha256=hashlib.sha256((ROOT/'src/tests/native/BrokerClassificationTests.cpp').read_bytes()).hexdigest(),
        installed=False,production_clients_permitted=False,loaded_driver_verified=False)
    if fault in ('service_cases','driver_cases','negative_controls'):result.pop(fault)
    elif fault=='float':result['service_cases']=90.0
    elif fault=='source':result['source_sha256']={}
    elif fault=='test':result['test_sha256']='0'*64
    elif fault:result[fault]=True
    path=tmp_path/'broker-classification/result.json';path.parent.mkdir();path.write_text(json.dumps(result))
    if fault:
        with pytest.raises(RuntimeError,match='Matching broker classification evidence'):tool.broker_classification_evidence(tmp_path,expected)
    else:assert tool.broker_classification_evidence(tmp_path,expected)==[path]
