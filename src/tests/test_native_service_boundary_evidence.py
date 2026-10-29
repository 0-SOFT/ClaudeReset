"""Packaging refuses missing, stale, or overstated service boundary evidence."""
import hashlib
import json
import pytest
from test_native_runtime_trust_evidence import tool,ROOT


@pytest.mark.parametrize('fault',[None,'manifest','source','fixture','missing','float','overclaim'])
@pytest.mark.parametrize('kind',['dispatch','handles','bootstrap'])
def test_service_evidence(tmp_path,kind,fault):
    folder=tmp_path/'service';folder.mkdir()
    name='Sandboxie/core/svc/CrBootstrapSecurity.h';sources={name:'a'*64}
    manifest={'files':{'CrBootstrapSecurity.h':{'prepared_sha256':'a'*64}}}
    cases={
        'dispatch':('native-dispatch-result.json','BrokerDispatchTests.cpp',dict(
            assertions=474,passed=True,installed_service_test=False,full_service_build_verified=False,
            production_clients_permitted=False,full_tunnel_verified=False)),
        'handles':('windows-handle-transfer-result.json','HandleTransferWindowsTests.cpp',dict(
            passed=True,process_access=1052672,thread_access=1050624,child_exited=True,
            identity_predicates_stubbed=True,installed_service_test=False,
            production_clients_permitted=False,full_tunnel_verified=False)),
        'bootstrap':('windows-bootstrap-security-result.json','BootstrapSecurityWindowsTests.cpp',dict(
            passed=True,checks=33,before_first_instruction=True,future_threads_verified=False,
            create_process_as_user_verified=False,caller_environment_excluded=True,
            production_clients_permitted=False))}
    for key,(filename,fixture,result) in cases.items():
        result.update(service_source_sha256=sources.copy(),test_sha256=hashlib.sha256(
            (ROOT/'src/tests/native'/fixture).read_bytes()).hexdigest())
        if key==kind:
            if fault=='source':result['service_source_sha256'][name]='b'*64
            if fault=='fixture':result['test_sha256']='b'*64
            if fault=='missing':result.pop('passed')
            if fault=='float':
                field={'dispatch':'assertions','handles':'process_access','bootstrap':'checks'}[kind]
                result[field]=float(result[field])
            if fault=='overclaim':result['production_clients_permitted']=True
        (folder/filename).write_text(json.dumps(result))
    if fault=='manifest':manifest['files']['CrBootstrapSecurity.h']['prepared_sha256']='b'*64
    (folder/'manifest.json').write_text(json.dumps(manifest))
    if fault:
        with pytest.raises(RuntimeError,match='[Ss]ervice'):
            tool.service_boundary_evidence(tmp_path,sources)
    else:
        assert len(tool.service_boundary_evidence(tmp_path,sources))==4
