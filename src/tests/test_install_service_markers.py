"""Real temporary durable journals; SCM and registry are modeled, never mutated."""
import ctypes as C
import json
from contextlib import contextmanager
import pytest
from claude_reset import install_service_markers as m
from claude_reset.install_service_receipts import ServiceReceipts
from claude_reset.install_journal import _LocalFile
from claude_reset.install_scm import specification,SERVICES
from claude_reset.safeio import SafetyError
from test_install_service_receipts import initial
from test_install_scm_cleanup import NativeModel
from test_install_registry_bind import acl


class Writer:
    def __init__(self):self.values={};self.events=[];self.failure=None;self.existing=False;self.bad=False
    def action(self,event):
        self.events.append(event)
        if self.failure==event:raise OSError('injected registry failure')
    def open(self,name):self.action('open');self.name=name;return 19
    def value(self,key,name):
        assert key==19
        if name=='SymbolicLinkValue':return None
        if self.existing:return 3,b'foreign'
        if self.bad and self.name in self.values:return 3,b'changed'
        return self.values.get(self.name)
    def protect(self,key):self.action('protect')
    def write_marker(self,key,data):self.action('write');self.values[self.name]=(3,data)
    def flush(self,key):self.action('flush')
    def security(self,key):self.action('security');return acl()
    def close_key(self,key):self.events.append('close')


@contextmanager
def setup(tmp_path):
    with _LocalFile(tmp_path) as journal:
        journal.save(initial());source=ServiceReceipts(journal);source.begin()
        receipts=m.MarkerReceipts(journal);native=NativeModel();writer=Writer()
        yield journal,source,receipts,native,writer
        for handle in list(native._created):native.release(handle)


def pending(source,native,name):
    spec=specification(name);source.record('intent',spec)
    marker=m.MarkerReceipts(source.journal).begin(spec)
    return spec,native.create(spec,creation_marker=marker)


def test_all_markers_bind_exact_service_generation_and_durable_prefix(tmp_path):
    with setup(tmp_path) as (journal,source,receipts,native,writer):
        for name in SERVICES:
            spec,handle=pending(source,native,name)
            assert m._mark_created_service(writer,native,handle,spec,receipts,lambda:True)==dict(
                marker_bound=True,service=name,client_admission=False,may_delete=False)
            source.record('disabled',spec)
        rows=receipts.load()['services']
        assert [row['marker']['service'] for row in rows]==list(SERVICES)
        assert all(row['state']=='bound' for row in rows)
        assert len({row['marker']['nonce'] for row in rows})==4
        for row in rows:
            marker=row['marker'];name=marker['service']
            assert writer.values[name]==(3,m.encoded(marker,specification(name),'a'*32,'b'*64))
        assert writer.events==['open','protect','write','flush','security','close']*4
        with pytest.raises(SafetyError):receipts.begin(specification(SERVICES[-1]))


@pytest.mark.parametrize('failure',['open','protect','write','flush','security','bound'])
def test_failed_binding_never_confirms_uncertain_ownership(tmp_path,monkeypatch,failure):
    with setup(tmp_path) as (_,source,receipts,native,writer):
        spec,handle=pending(source,native,SERVICES[0]);writer.failure=failure
        save=receipts.save
        def fail(value):
            if value['services'][-1]['state']==failure:raise OSError('receipt write failure')
            save(value)
        monkeypatch.setattr(receipts,'save',fail)
        with pytest.raises(OSError):m._mark_created_service(writer,native,handle,spec,receipts,lambda:True)
        record=receipts.load()
        assert record is None or record['services'][-1]['state']=='intent'
        if failure!='open':assert writer.events[-1]=='close'
        assert not native.deleted


@pytest.mark.parametrize('fault',['foreign-marker','readback','closed','released','different-service'])
def test_foreign_or_unheld_registration_is_not_claimed(tmp_path,fault):
    with setup(tmp_path) as (_,source,receipts,native,writer):
        spec,handle=pending(source,native,SERVICES[0])
        writer.existing=fault=='foreign-marker';writer.bad=fault=='readback'
        if fault=='released':native.release(handle)
        if fault=='different-service':native._created[handle]='SbieDrv'
        with pytest.raises(SafetyError):
            m._mark_created_service(writer,native,handle,spec,receipts,lambda:fault!='closed')
        if fault!='readback':assert 'write' not in writer.events
        assert not native.deleted


@pytest.mark.parametrize('field,value',[
    ('schema',True),('generation','c'*32),('package_sha256','d'*64),
    ('service','SbieDrv'),('nonce','bad'),('spec_sha256','e'*64)])
def test_marker_receipt_tampering_is_refused(tmp_path,field,value):
    with setup(tmp_path) as (_,source,receipts,native,writer):
        spec,handle=pending(source,native,SERVICES[0])
        m._mark_created_service(writer,native,handle,spec,receipts,lambda:True)
        record=receipts.load();record['services'][0]['marker'][field]=value
        receipts.path.write_bytes(json.dumps(record).encode())
        with pytest.raises(SafetyError):receipts.load()


def test_marker_native_write_is_fixed_reg_binary_and_has_no_create_or_delete_access():
    calls=[]
    class Api:
        def RegSetValueExW(self,key,name,reserved,kind,data,size):
            calls.append((key,name,reserved,kind,C.string_at(data,size)));return 0
    writer=m.Native.__new__(m.Native);writer.api=Api();writer.write_marker(19,b'fixture')
    assert calls==[(19,m.VALUE,0,3,b'fixture')]
    assert not m.ACCESS&(4|32|0x10000)
    with pytest.raises(SafetyError):writer.write_marker(19,b'x'*521)


@pytest.mark.parametrize('fault',['receipt-before-write','receipt-after-write','closed-after-intent','create','protect','sid','display'])
def test_precreation_failure_preserves_intent_without_claiming_ownership(tmp_path,monkeypatch,fault):
    from claude_reset.install_scm import _register_disabled,HeldRegistrations
    with setup(tmp_path) as (_,source,receipts,native,writer):
        saved=receipts.save
        def save(value):
            if fault=='receipt-before-write':raise OSError('not durable')
            saved(value)
            if fault=='receipt-after-write':raise OSError('durability unknown')
        monkeypatch.setattr(receipts,'save',save)
        created=native.create
        def create(spec,**kwargs):
            # The exact nonce is durable BEFORE the modeled SCM call.
            assert receipts.pending(spec)==kwargs['creation_marker']
            if fault=='create':raise OSError('SCM failed')
            handle=created(spec,**kwargs)
            if fault=='display':native.displays[spec['name']]=spec['name']
            return handle
        monkeypatch.setattr(native,'create',create)
        if fault in ('protect','sid'):native.model.failure=fault
        def closed():return not (fault=='closed-after-intent' and receipts.load() is not None)
        def mark(service,handle,spec):
            return m._mark_created_service(writer,service,handle,spec,receipts,closed)
        held=HeldRegistrations()
        try:
            with pytest.raises((SafetyError,OSError)):
                _register_disabled(native,SERVICES[0],source.record,closed,
                    prepare_service=mark,prepare_creation=receipts.begin,held=held)
            record=receipts.load()
            assert record is None or record['services'][-1]['state']=='intent'
            assert source.load()['services'][-1]['state']=='intent'
            assert not writer.values and not native.deleted
            if fault in ('receipt-before-write','receipt-after-write','closed-after-intent','create'):
                assert not native._created
        finally:held.close()


def test_missing_precreation_receipt_cannot_be_generated_after_creation(tmp_path):
    with setup(tmp_path) as (_,source,receipts,native,writer):
        spec=specification(SERVICES[0]);source.record('intent',spec);handle=native.create(spec)
        with pytest.raises(SafetyError,match='pre-creation'):
            m._mark_created_service(writer,native,handle,spec,receipts,lambda:True)
        assert receipts.load() is None and not writer.events


@pytest.mark.parametrize('name',SERVICES)
def test_creation_marker_is_part_of_same_native_create_call(tmp_path,monkeypatch,name):
    from claude_reset import install_scm as scm
    # Independent journal prefix for each fixed slot, no SCM/HKLM writes.
    with setup(tmp_path) as (_,source,receipts,native,writer):
        for earlier in SERVICES[:SERVICES.index(name)]:
            spec,handle=pending(source,native,earlier)
            m._mark_created_service(writer,native,handle,spec,receipts,lambda:True)
            source.record('disabled',spec)
        spec=specification(name);source.record('intent',spec);marker=receipts.begin(spec)
        calls=[]
        class Api:
            def CreateServiceW(self,*args):calls.append(args);return 91
        target=scm.Native.__new__(scm.Native);target.api=Api();target.manager=73
        monkeypatch.setattr(scm,'require_vacant_registry_slot',lambda value:None)
        assert target.create(spec,creation_marker=marker)==91
        assert len(calls)==1
        assert calls[0][:7]==(73,name,m.creation_display(marker,spec),scm.ACCESS,spec['type'],4,1)
        assert len(calls[0][2])<256 and marker['nonce'] in calls[0][2]
        assert target._created=={91:name}


@pytest.mark.parametrize('display',[None,'foreign display','ClaudeReset SbieDrv ['+'c'*64+']'])
def test_creation_snapshot_requires_exact_display_binding(tmp_path,display):
    with setup(tmp_path) as (_,source,receipts,native,writer):
        spec,handle=pending(source,native,SERVICES[0]);marker=receipts.pending(spec)
        actual=native.snapshot(handle,spec)
        if display is None:actual.pop('display')
        else:actual['display']=display
        with pytest.raises(SafetyError,match='creation binding'):
            m.validate_creation_snapshot(marker,spec,actual)


def test_native_snapshot_reads_display_from_query_service_config():
    from claude_reset import install_scm as scm
    spec=specification(SERVICES[0]);text='ClaudeReset atomic display fixture'
    config=scm.Config();config.type=spec['type'];config.start=4;config.error=1
    config.binary=spec['binary'];config.account=spec['account'];config.display=text
    class Api:
        def QueryServiceConfigW(self,handle,buffer,size,needed):
            C.cast(needed,C.POINTER(m.W.DWORD))[0]=C.sizeof(config)
            if buffer is None:return False
            C.memmove(buffer,C.byref(config),C.sizeof(config));return True
        def QueryServiceStatusEx(self,handle,kind,buffer,size,needed):
            status=C.cast(buffer,C.POINTER(scm.Status)).contents;status.state=1;status.pid=0;return True
    class Security:
        def read_handle(self,handle,name):return dict(name=name)
    native=scm.Native.__new__(scm.Native);native.api=Api();native.security=Security()
    result=native.snapshot(19,spec)
    assert result['display']==text and result['binary']==spec['binary']
    assert result['start']==4 and result['state']==1 and result['pid']==0
