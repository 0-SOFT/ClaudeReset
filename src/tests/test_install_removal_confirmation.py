"""Real receipt/files with modeled SCM absence; no native mutation APIs."""
import json
import pytest
from claude_reset import install_removal_confirmation as c
from claude_reset.install_recovery_inputs import RecoveryInputs
from claude_reset.install_removal_receipts import RemovalReceipts
from claude_reset.safeio import SafetyError
from test_install_attested_cleanup import setup,cleanup


def prepare(fixture,monkeypatch):
    step,inputs,held,native,state,_,handles=fixture
    state['pending']=True
    with pytest.raises(SafetyError,match='pending'):cleanup(fixture).run()
    assert held.closed and not handles and len(native.deleted)==4
    inputs.close();state['pending']=False
    # Actual administrative ACL acceptance is separate from these user fixtures.
    monkeypatch.setattr(c,'verify_paths',lambda *args:None)
    calls=[]
    def inspect(result,closed):
        assert closed() is True and not handles
        calls.append(result)
        if state['pending']:raise SafetyError('still present')
        return dict(services=native.deleted[:],absence_verified=True,client_admission=False)
    monkeypatch.setattr(c,'_confirm_removal',inspect)
    return calls


def test_fresh_inputs_confirm_absence_without_reopening_or_deleting_service(tmp_path,monkeypatch):
    with setup(tmp_path,monkeypatch) as fixture:
        step,_,_,native,state,_,_=fixture;calls=prepare(fixture,monkeypatch)
        with RecoveryInputs(step.store,step.generation) as inputs:
            result=c.confirm_recorded_removal(step.store,inputs,step.generation,lambda g:True)
            assert result==dict(services_removed=4,absence_verified=True,deletion_replayed=False,client_admission=False)
            assert c.confirm_recorded_removal(step.store,inputs,step.generation,lambda g:True)==result
        assert len(calls)==2 and len(native.deleted)==4
        assert RemovalReceipts(step.store.journal).load()['absence_verified'] is True
        assert json.loads((step.store.journal.directory/'boundary-receipt.json').read_bytes())['state']=='committed'


@pytest.mark.parametrize('fault',['partial','intent','pending','closed','generation','inputs','acl','boundary','marker','drift','reservation-drift','reservation-disappeared'])
def test_confirmation_refuses_ambiguous_or_changed_evidence(tmp_path,monkeypatch,fault):
    with setup(tmp_path,monkeypatch) as fixture:
        step,_,_,native,state,_,_=fixture;calls=prepare(fixture,monkeypatch)
        directory=step.store.journal.directory
        with RecoveryInputs(step.store,step.generation) as inputs:
            if fault in ('partial','intent'):
                path=directory/'service-removal-receipts.json';value=json.loads(path.read_bytes())
                if fault=='partial':value['services'].pop()
                else:value['services'][-1]['state']='delete_intent'
                path.write_bytes(json.dumps(value).encode())
            if fault=='inputs':inputs.close()
            if fault=='pending':state['pending']=True
            if fault=='acl':
                def refused(*args):raise SafetyError('untrusted metadata')
                monkeypatch.setattr(c,'verify_paths',refused)
            if fault in ('boundary','marker'):
                name='boundary-receipt.json' if fault=='boundary' else 'service-marker-receipts.json'
                path=directory/name;value=json.loads(path.read_bytes())
                if fault=='boundary':value['state']='removed'
                else:value['services'][-1]['state']='intent'
                path.write_bytes(json.dumps(value).encode())
            if fault in ('drift','reservation-drift','reservation-disappeared'):
                original=c._confirm_removal
                def changed(result,closed):
                    answer=original(result,closed)
                    if fault=='drift':
                        value=step.store.journal.load();value['state']='recovery_required';step.store.journal.save(value)
                    else:
                        path=directory/'reservation-receipt.json'
                        if fault=='reservation-disappeared':path.unlink()
                        else:
                            value=json.loads(path.read_bytes());value['keys']=list(reversed(value['keys']))
                            path.write_bytes(json.dumps(value).encode())
                    return answer
                monkeypatch.setattr(c,'_confirm_removal',changed)
            with pytest.raises(SafetyError):
                c.confirm_recorded_removal(step.store,inputs,'f'*32 if fault=='generation' else step.generation,
                                           lambda g:fault!='closed')
        assert len(native.deleted)==4
        assert json.loads((directory/'service-removal-receipts.json').read_bytes())['absence_verified'] is False
