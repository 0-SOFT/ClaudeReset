"""Protected temporary staging plus query-model services and BFE."""
import json
from contextlib import contextmanager
import pytest
from claude_reset import install_reservation_observation as r,install_recovery_inputs as ri
from claude_reset.install_service_attestation import HeldAttestation
from claude_reset.install_boundary import _held_rules
from claude_reset.backend_spec import decode
from claude_reset.safeio import SafetyError
from test_install_service_step import prepared
from test_install_service_attestation import readers
from test_install_reservations import Parent,View


@contextmanager
def fixture(tmp_path,monkeypatch,present=False,phase='intent',*,signed=None):
    with prepared(tmp_path,monkeypatch,signed=signed) as (step,tx,_,native):
        step.apply();step.held.close();tx['state']='recovering';step.store.journal.save(tx)
        _,handles,keys,_=readers(step,native,monkeypatch)
        monkeypatch.setattr(ri,'program_files',lambda:tmp_path);monkeypatch.setattr(ri,'verify_paths',lambda *args:None)
        monkeypatch.setattr(r,'verify_paths',lambda *args:None);monkeypatch.setattr(r,'verify_image',lambda *args:None)
        monkeypatch.setattr(r,'listeners',lambda ports:[]);monkeypatch.setattr(r,'Reservation',View)
        state=dict(present=present,strict=True,closed=True);parents=[]
        with ri.RecoveryInputs(step.store,step.generation) as inputs:
            spec=decode(inputs.configuration.pins['Backend/backend.json'].data)
            strict={v.key.value() for v in _held_rules(step.store,inputs.payload)}
            dummy=Parent()
            views=[View(None,'ClaudeResetBackend',spec['backend_port'],engine=dummy),
                   View(None,'ClaudeResetGateway',spec['gateway_port'],engine=dummy)]
            reserved=[v.native(layer,allow)[0].filterKey.value() for v in views for layer in r.LAYERS for allow in (False,True)]
            path=step.store.journal.directory/r.ReservationReceipt.filename;value=json.loads(path.read_bytes())
            value.update(keys=reserved,state=phase);path.write_bytes(json.dumps(value).encode())
            def factory():
                parent=Parent();parent.layer=state['present'];parent.added=set(reserved) if state['present'] else set()
                parent.existing_sublayer=lambda:state['strict'];parent.own_keys=lambda:strict
                parent.exists_verified=lambda rule:state['strict'];parents.append(parent)
                original=parent._call;committed=[False]
                def call(name,signature,*args):
                    allowed=('FwpmTransactionBegin0','FwpmTransactionAbort0')
                    if state.get('allow_mutation'):allowed+=('FwpmFilterDeleteByKey0','FwpmSubLayerDeleteByKey0','FwpmTransactionCommit0')
                    assert name in allowed
                    if name=='FwpmTransactionBegin0':assert args[-1] in ((0,1) if state.get('allow_mutation') else (1,))
                    if name=='FwpmTransactionCommit0' and state.get('fault')=='before-commit':raise SafetyError('commit refused')
                    if name=='FwpmTransactionAbort0' and committed[0]:return None
                    result=original(name,signature,*args)
                    if name=='FwpmTransactionCommit0':
                        committed[0]=True
                        if state.get('fault')=='after-commit':raise SafetyError('commit reply lost')
                    return result
                parent._call=call;original_close=parent.close
                def close():
                    state['present']=parent.layer
                    original_close()
                    if state.get('on_close'):state['on_close']()
                parent.close=close;return parent
            monkeypatch.setattr(r,'Engine',factory)
            with HeldAttestation(step.store,step.generation) as held:
                yield step,inputs,held,native,state,parents,path


@pytest.mark.parametrize('phase',['intent','committed','remove_intent','removed'])
def test_absent_pair_is_confirmed_without_replaying_or_changing_service_history(tmp_path,monkeypatch,phase):
    with fixture(tmp_path,monkeypatch,phase=phase) as f:
        step,inputs,held,native,state,parents,path=f
        source=(step.store.journal.directory/'service-receipts.json').read_bytes()
        result=r.reconcile_reservation_absence(step.store,inputs,held,step.generation,lambda g:state['closed'])
        assert result==dict(reservations_absent=True,deletion_replayed=False,client_admission=False)
        value=json.loads(path.read_bytes());assert value['previous_state']==phase and value['state']=='removed'
        assert (step.store.journal.directory/'service-receipts.json').read_bytes()==source and not native.deleted
        assert all(p.events==['FwpmTransactionBegin0','FwpmTransactionAbort0','parent-close'] for p in parents)


@pytest.mark.parametrize('fault',['present','strict','closed','occupied','handles','acl','boundary'])
def test_unknown_reservation_or_missing_protection_never_becomes_removed(tmp_path,monkeypatch,fault):
    with fixture(tmp_path,monkeypatch,present=fault=='present') as f:
        step,inputs,held,native,state,parents,path=f;before=path.read_bytes()
        if fault in ('strict','closed'):state[fault]=False
        if fault=='occupied':monkeypatch.setattr(r,'listeners',lambda ports:[dict(port=ports[0])])
        if fault=='handles':held.close()
        if fault=='acl':
            def refused(*args):raise SafetyError('unprotected metadata')
            monkeypatch.setattr(r,'verify_paths',refused)
        if fault=='boundary':
            boundary=step.store.journal.directory/'boundary-receipt.json';value=json.loads(boundary.read_bytes())
            value['state']='remove_intent';boundary.write_bytes(json.dumps(value).encode())
        with pytest.raises(SafetyError):r.reconcile_reservation_absence(step.store,inputs,held,step.generation,lambda g:state['closed'])
        assert path.read_bytes()==before and not native.deleted


@pytest.mark.parametrize('fault',['receipt','closed','policy'])
def test_query_session_close_cannot_hide_changed_evidence(tmp_path,monkeypatch,fault):
    with fixture(tmp_path,monkeypatch) as f:
        step,inputs,held,native,state,parents,path=f
        def changed():
            if fault=='closed':state['closed']=False
            else:
                target=path if fault=='receipt' else step.store.journal.directory/'policy-binding-receipt.json'
                value=json.loads(target.read_bytes());value['state']='committed' if fault=='receipt' else 'intent'
                target.write_bytes(json.dumps(value).encode())
        state['on_close']=changed
        with pytest.raises(SafetyError):r.reconcile_reservation_absence(step.store,inputs,held,step.generation,lambda g:state['closed'])
        assert json.loads(path.read_bytes())['schema']==1 and not native.deleted
