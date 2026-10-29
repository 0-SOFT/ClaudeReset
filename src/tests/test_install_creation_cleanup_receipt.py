from copy import deepcopy
import pytest
from claude_reset.install_creation_cleanup_receipt import CreationCleanupReceipt
from claude_reset.safeio import SafetyError
from test_install_creation_attestation import pending


def observation(receipt):
    return dict(services=[receipt.context()['service']],absence_verified=True,client_admission=False)


@pytest.mark.parametrize('outcome',['no-request','unknown','requested'])
def test_absence_preserves_actual_request_history(tmp_path,monkeypatch,outcome):
    with pending(tmp_path,monkeypatch,present=False) as (step,*_):
        receipt=CreationCleanupReceipt(step.store,step.generation)
        source=(step.store.journal.directory/'service-receipts.json').read_bytes()
        if outcome!='no-request':
            identifier=receipt.begin()
            if outcome=='requested':receipt.requested(identifier)
        before=receipt.load()
        receipt.observe_absence(observation(receipt))
        assert receipt.load()['attempts']==([] if before is None else before['attempts'])
        assert receipt.load()['absence_verified'] is True
        with pytest.raises(SafetyError):receipt.begin()
        assert (step.store.journal.directory/'service-receipts.json').read_bytes()==source


def test_uncertain_attempts_are_retained_and_known_request_never_replayed(tmp_path,monkeypatch):
    with pending(tmp_path,monkeypatch) as (step,*_):
        receipt=CreationCleanupReceipt(step.store,step.generation)
        first=receipt.begin();second=receipt.begin()
        with pytest.raises(SafetyError):receipt.requested(first)
        receipt.requested(second)
        assert receipt.load()['attempts']==[dict(id=first,state='delete_intent'),dict(id=second,state='delete_requested')]
        with pytest.raises(SafetyError):receipt.begin()
        with pytest.raises(SafetyError):receipt.requested(second)


@pytest.mark.parametrize('fault',['schema','source','duplicate','replay','limit','admission','scope','boolean'])
def test_invalid_or_mismatched_evidence_refuses(tmp_path,monkeypatch,fault):
    with pending(tmp_path,monkeypatch) as (step,*_):
        receipt=CreationCleanupReceipt(step.store,step.generation);receipt.begin()
        original=receipt.load();value=deepcopy(original)
        if fault=='schema':value['schema']=True
        if fault=='source':value['evidence_sha256']='0'*64
        if fault=='duplicate':value['attempts']*=2
        if fault=='replay':
            value['attempts'][0]['state']='delete_requested'
            value['attempts'].append(dict(id='f'*32,state='delete_intent'))
        if fault=='limit':value['attempts']=[dict(id=f'{i:032x}',state='delete_intent') for i in range(17)]
        if fault in ('admission','scope','boolean'):
            observed=observation(receipt)
            if fault=='admission':observed['client_admission']=True
            if fault=='scope':observed['services']=[]
            if fault=='boolean':observed['absence_verified']=1
            with pytest.raises(SafetyError):receipt.observe_absence(observed)
        else:
            with pytest.raises(SafetyError):receipt.save(value)
        assert receipt.load()==original
