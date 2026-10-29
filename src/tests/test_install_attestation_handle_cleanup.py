from types import SimpleNamespace
import pytest
from claude_reset.install_service_attestation import HeldAttestation,NativeReader,RegistryReader
from claude_reset.install_creation_attestation import HeldPendingCreation
from claude_reset.safeio import SafetyError


@pytest.mark.parametrize('kind',['marked','pending'])
@pytest.mark.parametrize('fault',['service','key','manager','both'])
def test_attestation_cleanup_attempts_all_resources_and_retains_failed_ones(kind,fault):
    services={17,18} if kind=='marked' else {17}
    keys={27,28} if kind=='marked' else {27}
    bad_services={17} if fault in ('service','both') else set()
    bad_keys={27} if fault in ('key','both') else set()
    manager_bad=[fault=='manager'];manager_live=[True]
    class Reader:
        def release(self,handle):
            if handle in bad_services:raise SafetyError('service close failed')
            services.remove(handle)
        def close(self):
            if manager_bad[0]:raise SafetyError('manager close failed')
            manager_live[0]=False
    class Registry:
        def close_key(self,key):
            if key in bad_keys:raise SafetyError('key close failed')
            keys.remove(key)
    cls=HeldAttestation if kind=='marked' else HeldPendingCreation
    held=cls.__new__(cls);held.reader=Reader();held.registry=Registry();held.closed=False
    if kind=='marked':held.items=[(17,27,{'name':'one'}),(18,28,{'name':'two'})]
    else:held.handle=17;held.key=27
    with pytest.raises(SafetyError):held.close()
    assert held.closed and services==bad_services and keys==bad_keys
    with pytest.raises(SafetyError):held.verify()
    assert manager_live[0]==manager_bad[0]
    if services or manager_live[0]:assert held.reader is not None
    bad_services.clear();bad_keys.clear();manager_bad[0]=False
    held.close()
    assert not services and not keys and not manager_live[0] and held.reader is None
    held.close()  # A completed cleanup is idempotent; no double close.


def test_native_query_handle_close_failure_is_reported():
    reader=NativeReader.__new__(NativeReader)
    reader.api=SimpleNamespace(CloseServiceHandle=lambda handle:False)
    with pytest.raises(SafetyError):reader.release(17)


def test_native_registry_key_close_failure_is_reported():
    reader=RegistryReader.__new__(RegistryReader)
    reader.api=SimpleNamespace(RegCloseKey=lambda key:5)
    with pytest.raises(SafetyError):reader.close_key(27)


def test_completed_deletions_retry_failed_query_close_without_redeletion(tmp_path,monkeypatch):
    from test_install_attested_cleanup import setup,cleanup
    from claude_reset.install_removal_receipts import RemovalReceipts
    with setup(tmp_path,monkeypatch) as fixture:
        step,_,held,native,_,_,handles=fixture;operation=cleanup(fixture)
        release=held.reader.release;failed=[False]
        def fail_once(handle):
            if not failed[0]:
                failed[0]=True;raise SafetyError('query close failed')
            release(handle)
        held.reader.release=fail_once
        with pytest.raises(SafetyError):operation.run()
        assert held.closed and len(held.items)==1 and len(handles)==1
        assert len(native.deleted)==4
        receipt=RemovalReceipts(step.store.journal).load()
        assert receipt['absence_verified'] is False
        assert all(row['state']=='delete_requested' for row in receipt['services'])
        assert operation.run()['absence_verified'] is True
        assert len(native.deleted)==4 and not handles and not held.items


def test_pending_creation_keeps_failed_query_handle_but_does_not_replay(tmp_path,monkeypatch):
    from test_install_creation_cleanup import setup,operation
    from claude_reset.install_creation_cleanup_receipt import CreationCleanupReceipt
    with setup(tmp_path,monkeypatch) as fixture:
        step,_,held,native,_,handles,_=fixture;cleanup=operation(fixture)
        reader=held.reader;release=reader.release
        reader.release=lambda handle:(_ for _ in ()).throw(SafetyError('query close failed'))
        try:
            with pytest.raises(SafetyError):cleanup.run()
            assert held.closed and held.handle is not None and held.reader is reader
            receipt=CreationCleanupReceipt(step.store,step.generation).load()
            assert not receipt['absence_verified'] and receipt['attempts'][-1]['state']=='delete_requested'
            with pytest.raises(SafetyError):cleanup.run()
            assert len(native.deleted)==1
        finally:reader.release=release
        held.close()
        assert not handles and held.handle is None and held.reader is None
        assert CreationCleanupReceipt(step.store,step.generation).load()['absence_verified'] is False
