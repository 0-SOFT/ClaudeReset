import ctypes as C
import uuid
import pytest
from claude_reset import install_reservations as r,gateway_reservation as g,strict_wfp as w
from claude_reset.safeio import SafetyError


class Parent(w.Engine):
    def __init__(self,failure=None):
        self.handle=17;self.dynamic=False;self._transaction=False;self.failure=failure
        self.events=[];self.added=set();self.layer=False
    def close(self):self.events.append('parent-close');self.handle=None
    def _free(self,pointer):self.events.append('free')
    def _call(self,name,signature,*args,**kwargs):
        self.events.append(name)
        if name=='FwpmTransactionBegin0':self.before=(set(self.added),self.layer)
        if name=='FwpmFilterAdd0':
            self.added.add(C.cast(args[1],C.POINTER(w.wfp.FILTER)).contents.filterKey.value())
            if self.failure=='second-role' and len(self.added)==9:raise SafetyError('injected')
        if name=='FwpmTransactionCommit0' and self.failure=='commit':raise SafetyError('injected')
        if name=='FwpmFilterDeleteByKey0':
            self.added.remove(C.cast(args[1],C.POINTER(w.wfp.GUID)).contents.value())
            if self.failure=='delete':raise SafetyError('injected')
        if name=='FwpmSubLayerDeleteByKey0':
            assert C.cast(args[1],C.POINTER(w.wfp.GUID)).contents.value()==g.SUB.value()
            self.layer=False
        if name=='FwpmTransactionAbort0':self.added,self.layer=self.before


class View(g.Reservation):
    def __init__(self,path,service,port,*,engine):
        self.service=service;self.port=port;self._borrowed_engine=engine;self._borrowed_closed=False
        self.handle=engine.handle;self.dynamic=False;self._transaction=False
    def existing_sublayer(self):return self._borrowed_engine.layer or self._borrowed_engine.failure=='existing'
    def own_keys(self):return set(self._borrowed_engine.added)
    def ensure_sublayer(self):
        parent=self._borrowed_engine;assert parent._transaction
        parent.layer=True;parent.events.append('sublayer')
        if parent.failure=='sublayer':raise SafetyError('injected')
    def native(self,layer,allow):
        key=uuid.uuid5(g.NS,f'{self.service}:{self.port}:{layer}:{allow}')
        return w.wfp.FILTER(filterKey=w.wfp.GUID.of(key)),[]
    def verified(self,layer,allow):
        parent=self._borrowed_engine
        return self.native(layer,allow)[0].filterKey.value() in parent.added and parent.failure!='readback'


def pair(parent):
    return [View(None,'ClaudeResetBackend',1080,engine=parent),View(None,'ClaudeResetGateway',1081,engine=parent)]


def test_both_port_reservations_commit_in_one_transaction():
    parent=Parent();r._install_pair(parent,pair(parent),lambda:True)
    assert len(parent.added)==16 and parent.layer and not parent._transaction
    assert parent.events==['FwpmTransactionBegin0','sublayer']+['FwpmFilterAdd0']*16+['FwpmTransactionCommit0']


@pytest.mark.parametrize('failure',['sublayer','second-role','readback','commit','closed-after'])
def test_second_port_or_later_failure_aborts_all_reservations(failure):
    parent=Parent(failure);calls=[0]
    def closed():calls[0]+=1;return failure!='closed-after' or calls[0]==1
    with pytest.raises(SafetyError):r._install_pair(parent,pair(parent),closed)
    assert parent.events[-1]=='FwpmTransactionAbort0' and not parent.added and not parent.layer


@pytest.mark.parametrize('fault',['existing','ports','service','session','dynamic','closed'])
def test_unaccepted_pair_never_begins(fault):
    parent=Parent('existing' if fault=='existing' else None);views=pair(parent)
    if fault=='ports':views[1].port=1080
    if fault=='service':views[1].service='BITS'
    if fault=='session':views[1]._borrowed_engine=Parent()
    if fault=='dynamic':parent.dynamic=True
    if fault=='closed':views[1]._borrowed_closed=True
    with pytest.raises(SafetyError):r._install_pair(parent,views,lambda:True)
    assert not parent.events


def test_borrowed_reservation_closes_only_view_and_never_parent(tmp_path,monkeypatch):
    monkeypatch.setattr(g,'service_descriptor',lambda name:b'fixture descriptor')
    path=tmp_path/'engine.exe';path.write_bytes(b'inert');parent=Parent()
    view=g.Reservation(path,'ClaudeResetBackend',1080,engine=parent)
    view._call('read',[]);view.close()
    assert parent.handle==17 and parent.events==['read']
    with pytest.raises(SafetyError):view._call('read',[])
    with pytest.raises(SafetyError):view.install()
    assert parent.handle==17


def test_borrowed_view_cannot_use_closed_parent(tmp_path,monkeypatch):
    monkeypatch.setattr(g,'service_descriptor',lambda name:b'fixture descriptor')
    path=tmp_path/'engine.exe';path.write_bytes(b'inert');parent=Parent()
    view=g.Reservation(path,'ClaudeResetBackend',1080,engine=parent);parent.close()
    with pytest.raises(SafetyError):view._call('read',[])


@pytest.mark.parametrize('fault',[None,'extra','missing','readback','delete','commit','closed-after'])
def test_pair_cleanup_preserves_whole_boundary_on_failure(fault):
    parent=Parent();views=pair(parent);r._install_pair(parent,views,lambda:True)
    parent.events.clear();parent.failure=fault
    if fault=='extra':parent.added.add(str(uuid.uuid4()))
    if fault=='missing':parent.added.pop()
    before=set(parent.added);calls=[0]
    def closed():calls[0]+=1;return fault!='closed-after' or calls[0]==1
    if fault:
        with pytest.raises(SafetyError):r._remove_pair(parent,views,closed)
        assert parent.added==before and parent.layer
        if fault in ('extra','missing','readback'):assert not parent.events
        else:assert parent.events[-1]=='FwpmTransactionAbort0'
    else:
        r._remove_pair(parent,views,closed)
        assert not parent.added and not parent.layer
        assert parent.events==['FwpmTransactionBegin0']+['FwpmFilterDeleteByKey0']*16+['FwpmSubLayerDeleteByKey0','FwpmTransactionCommit0']


@pytest.mark.parametrize('fault,attested',[(fault,False) for fault in
    [None,'occupied','service-drift','strict-drift','second-role','remove-commit']]+
    [(None,True),('remove-commit',True),('marker-drift',True),('attested-closed',True)])
def test_staged_reservations_and_ordered_recovery(tmp_path,monkeypatch,fault,attested):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from claude_reset import install_boundary as b,install_scm as scm,service_store,tcp_inventory
    from claude_reset import install_service_step as step_module
    from claude_reset.install_service_attestation import HeldAttestation
    from claude_reset.install_service_markers import MarkerReceipts,_mark_created_service
    from claude_reset.install_stage import _stage_payload
    from claude_reset.install_config_stage import _stage_configuration
    from claude_reset.install_binding_receipts import BindingReceipt
    from claude_reset.install_service_receipts import ServiceReceipts
    from claude_reset.install_removal_receipts import RemovalReceipts
    from test_install_config_stage import fixture
    from test_install_scm_cleanup import NativeModel
    from test_install_service_markers import Writer
    from test_install_service_attestation import readers
    parent=Parent('second-role' if fault=='second-role' else None)
    # The native session and SCM are modeled. Files/identities/journal are real.
    monkeypatch.setattr(r,'Engine',lambda:parent)
    monkeypatch.setattr(r,'Reservation',View)
    # Preserve isinstance validation when replacing the constructor.
    original_validate=r._validate_pair
    def validate(engine,views):
        with monkeypatch.context() as patch:
            patch.setattr(r,'Engine',w.Engine);original_validate(engine,views)
    monkeypatch.setattr(r,'_validate_pair',validate)
    parent.close=lambda:None
    parent.existing_sublayer=lambda:fault!='strict-drift'
    parent.exists_verified=lambda rule:True
    monkeypatch.setattr(b,'program_files',lambda:tmp_path)
    monkeypatch.setattr(scm,'program_files',lambda:tmp_path)
    monkeypatch.setattr(step_module,'program_files',lambda:tmp_path)
    monkeypatch.setattr(service_store,'verify_image',lambda path,service:None)
    monkeypatch.setattr(tcp_inventory,'listeners',lambda ports:[{'pid':42}] if fault=='occupied' else [])
    with fixture(tmp_path,monkeypatch,root_name='ClaudeReset') as (store,payload,tx,spec,data):
        with _stage_payload(store,payload,'a'*32,lambda g:True) as staged,_stage_configuration(
                store,payload,'a'*32,spec,data,['C:\\'],lambda g:True) as config,scm.HeldRegistrations() as held:
            tx['entries'][-1]['state']='done';tx['entries'].append(dict(step='install_services',state='intent'));store.journal.save(tx)
            deny=r.BoundaryReceipt(store.journal,[rule.key.value() for rule in b._held_rules(store,staged)])
            deny.record('intent');deny.record('committed')
            registered=ServiceReceipts(store.journal);registered.begin();native=NativeModel()
            writer=Writer()
            def marker(service,handle,spec):
                return _mark_created_service(writer,service,handle,spec,MarkerReceipts(store.journal),lambda:True)
            def bind(*args):
                pin=config.pins['Policy/Sandboxie.ini'];receipt=BindingReceipt(store.journal,pin)
                receipt.record('intent',pin.sha256);receipt.record('bound',pin.sha256)
                return dict(policy_bound=True,driver_started=False,client_admission=False)
            for name in scm.SERVICES:
                scm._register_disabled(native,name,registered.record,lambda:True,
                    held=held,prepare_driver=bind if name=='SbieDrv' else None,
                    prepare_service=marker if attested else None,
                    prepare_creation=MarkerReceipts(store.journal).begin if attested else None)
            if fault=='service-drift':native.changed=True
            if fault not in (None,'remove-commit','marker-drift','attested-closed'):
                with pytest.raises(SafetyError):r._install_initial_reservations(store,staged,config,'a'*32,held,lambda g:True)
                assert not parent.added
                return
            result=r._install_initial_reservations(store,staged,config,'a'*32,held,lambda g:True)
            assert result==dict(reservation_filters=16,client_admission=False)
            tx['state']='recovering';store.journal.save(tx)
            with pytest.raises(SafetyError):RemovalReceipts(store.journal).context()
            keys=sorted(parent.added);original=set(parent.added)
            opened=nullcontext(held);remove=r._remove_initial_reservations
            if attested:
                held.close();assert not native._created
                _,_,_,marker_values=readers(SimpleNamespace(store=store,generation='a'*32),native,monkeypatch)
                opened=HeldAttestation(store,'a'*32);remove=r._remove_attested_initial_reservations
            with opened as recovery:
                if attested:
                    before=list(parent.events)
                    with pytest.raises(SafetyError):r._install_initial_reservations(store,staged,config,'a'*32,recovery,lambda g:True)
                    assert parent.events==before
                if fault in ('marker-drift','attested-closed'):
                    if fault=='marker-drift':marker_values['SbieDrv']=(3,b'changed')
                    before=list(parent.events)
                    with pytest.raises(SafetyError):remove(store,staged,config,'a'*32,recovery,lambda g:fault!='attested-closed')
                    assert parent.events==before and parent.added==original
                    assert not native.deleted
                    return
                if fault=='remove-commit':
                    parent.failure='commit'
                    with pytest.raises(SafetyError):remove(store,staged,config,'a'*32,recovery,lambda g:True)
                    assert parent.added==original
                    with pytest.raises(SafetyError):RemovalReceipts(store.journal).context()
                    with pytest.raises(SafetyError):remove(store,staged,config,'a'*32,recovery,lambda g:True)
                else:
                    assert remove(store,staged,config,'a'*32,recovery,lambda g:True)==dict(reservation_filters_removed=16,client_admission=False)
                    assert not parent.added and not parent.layer
                    assert len(RemovalReceipts(store.journal).context()[1])==4
            assert len(held.items)==(0 if attested else 4) and not native.deleted and len(keys)==16


def test_reservation_enumeration_does_not_count_strict_or_foreign_sublayers():
    from ctypes import wintypes as W
    parent=Parent();view=pair(parent)[0]
    keys=[w.wfp.GUID.of(uuid.uuid4()) for _ in range(3)]
    filters=[w.wfp.FILTER(filterKey=key,subLayerKey=sub) for key,sub in
             zip(keys,[g.SUB,w.SUBKEY,w.wfp.GUID.of(uuid.uuid4())])]
    pointers=(C.POINTER(w.wfp.FILTER)*3)(*[C.pointer(f) for f in filters])
    def call(name,signature,*args,**kwargs):
        parent.events.append(name)
        if name=='FwpmFilterCreateEnumHandle0':C.cast(args[2],C.POINTER(W.HANDLE))[0]=91
        if name=='FwpmFilterEnum0':
            C.cast(args[3],C.POINTER(C.POINTER(C.POINTER(w.wfp.FILTER))))[0]=pointers
            C.cast(args[4],C.POINTER(W.DWORD))[0]=3
    parent._call=call
    assert g.Reservation.own_keys(view)=={keys[0].value()}
    assert parent.own_keys()=={keys[1].value()}
    assert parent.events.count('free')==2
    assert parent.events.count('FwpmFilterDestroyEnumHandle0')==2


@pytest.mark.parametrize('state',['intent','committed','remove_intent','removed','invalid','wrong-generation'])
def test_reservation_receipt_order_gate_is_fail_closed(tmp_path,state):
    import json
    from claude_reset.install_journal import _LocalFile
    from test_install_service_receipts import initial
    with _LocalFile(tmp_path) as journal:
        tx=initial();journal.save(tx)
        keys=[str(uuid.uuid4()) for _ in range(16)]
        value=dict(schema=1,generation=tx['generation'],package_sha256=tx['package_sha256'],keys=keys,state=state)
        if state=='wrong-generation':value.update(generation='f'*32,state='removed')
        (tmp_path/r.ReservationReceipt.filename).write_text(json.dumps(value))
        if state=='removed':r.ReservationReceipt.require_removed_if_present(journal)
        else:
            with pytest.raises(SafetyError):r.ReservationReceipt.require_removed_if_present(journal)
