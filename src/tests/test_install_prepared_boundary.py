"""Real protected-data fixtures, modeled SCM/registry and query-only BFE."""
import json
from contextlib import contextmanager
import pytest
from claude_reset import install_prepared_boundary as p
from claude_reset.backend_spec import decode
from claude_reset.install_boundary import _held_rules
from claude_reset.safeio import SafetyError
from test_install_service_step import prepared
from test_install_reservations import Parent,View

VERIFY=p.verify_prepared_boundary


@contextmanager
def fixture(tmp_path,monkeypatch):
    with prepared(tmp_path,monkeypatch) as (step,tx,_,native):
        step.apply()
        monkeypatch.setattr(p,'verify_image',lambda *args:None)
        monkeypatch.setattr(p,'listeners',lambda ports:[])
        monkeypatch.setattr(p,'Reservation',View)
        spec=decode(step.configuration.pins['Backend/backend.json'].data)
        parent=Parent();parent.layer=True
        views=[View(None,'ClaudeResetBackend',spec['backend_port'],engine=parent),
               View(None,'ClaudeResetGateway',spec['gateway_port'],engine=parent)]
        reserved=[v.native(layer,allow)[0].filterKey.value() for v in views for layer in p.LAYERS for allow in (False,True)]
        parent.added=set(reserved)
        strict={r.key.value() for r in _held_rules(step.store,step.payload)}
        parent.existing_sublayer=lambda:True;parent.own_keys=lambda:set(strict)
        parent.exists_verified=lambda rule:True
        path=step.store.journal.directory/p.ReservationReceipt.filename
        value=json.loads(path.read_bytes());value['keys']=reserved;path.write_bytes(json.dumps(value).encode())
        real=parent._call
        def query(name,signature,*args):
            assert name in ('FwpmTransactionBegin0','FwpmTransactionAbort0')
            if name=='FwpmTransactionBegin0':assert args[-1]==1
            return real(name,signature,*args)
        parent._call=query;monkeypatch.setattr(p,'Engine',lambda:parent)
        yield step,tx,native,parent,path


def run(step):
    return VERIFY(step.store,step.payload,step.configuration,step.generation,step.held,step.verifier)


def test_complete_prepared_boundary_is_one_query_transaction_without_resource_changes(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (step,tx,native,parent,path):
        before={p:p.read_bytes() for p in step.store.journal.directory.glob('*.json')}
        result=run(step)
        assert result==dict(deny_filters_verified=16,reservation_filters_verified=16,wfp_snapshot_consistent=True,
                           services_started=False,client_admission=False)
        assert parent.events==['FwpmTransactionBegin0','FwpmTransactionAbort0','parent-close']
        assert all(p.read_bytes()==raw for p,raw in before.items()) and not native.deleted


@pytest.mark.parametrize('fault',['denies-absent','extra-deny','deny-changed','reservation-absent','extra-reservation',
    'reservation-changed','intent','wrong-keys','occupied','unknown-listeners','running','marker','closed','released-policy'])
def test_incomplete_prepared_boundary_never_reports_success(tmp_path,monkeypatch,fault):
    with fixture(tmp_path,monkeypatch) as (step,tx,native,parent,path):
        if fault=='denies-absent':parent.existing_sublayer=lambda:False
        if fault=='extra-deny':
            real=parent.own_keys;parent.own_keys=lambda:real()|{'extra'}
        if fault=='deny-changed':parent.exists_verified=lambda rule:False
        if fault=='reservation-absent':parent.layer=False;parent.added.clear()
        if fault=='extra-reservation':parent.added.add('extra')
        if fault=='reservation-changed':parent.failure='readback'
        if fault in ('intent','wrong-keys'):
            value=json.loads(path.read_bytes())
            if fault=='intent':value['state']='intent'
            else:value['keys']=list(reversed(value['keys']))
            path.write_bytes(json.dumps(value).encode())
        if fault=='occupied':monkeypatch.setattr(p,'listeners',lambda ports:[dict(port=ports[0])])
        if fault=='unknown-listeners':monkeypatch.setattr(p,'listeners',lambda ports:None)
        if fault=='running':native.changed=True
        if fault=='marker':native.registry_fixture.values['ClaudeResetBackend']=(3,b'changed')
        if fault=='closed':step.verifier=lambda g:False
        if fault=='released-policy':step.configuration.pins['Policy/Sandboxie.ini'].close()
        before=path.read_bytes()
        with pytest.raises(SafetyError):run(step)
        assert path.read_bytes()==before and not native.deleted
        assert set(parent.events)<= {'FwpmTransactionBegin0','FwpmTransactionAbort0','parent-close'}


@pytest.mark.parametrize('fault',['receipt','marker','closed'])
def test_changed_evidence_during_session_close_invalidates_success(tmp_path,monkeypatch,fault):
    with fixture(tmp_path,monkeypatch) as (step,tx,native,parent,path):
        available=[True];step.verifier=lambda g:available[0]
        close=parent.close
        def changed():
            close()
            if fault=='receipt':
                value=json.loads(path.read_bytes());value['state']='intent';path.write_bytes(json.dumps(value).encode())
            if fault=='marker':native.registry_fixture.values['SbieDrv']=(3,b'changed')
            if fault=='closed':available[0]=False
        parent.close=changed
        with pytest.raises(SafetyError):run(step)
        assert not native.deleted
