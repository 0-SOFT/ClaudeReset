from copy import deepcopy
import pytest
from claude_reset import install_transaction as t
from claude_reset.safeio import SafetyError


class Adapter:
    def __init__(self, failure=None):
        self.failure = failure
        self.events = []
        self.journal = None
        self.resources = set()
        self.permits = False

    def event(self, name):
        self.events.append(name)
        if self.failure == name:
            self.failure = None
            raise OSError('injected failure')

    def preflight(self, generation, package): self.event('preflight')
    def save(self, value):
        self.event('save:' + value['state'])
        self.journal = deepcopy(value)
    def apply(self, step, generation):
        assert self.journal['entries'][-1] == {'step': step, 'state': 'intent'}
        self.resources.add(step)  # Failure may occur after mutation.
        self.event('apply:' + step)
    def undo(self, step, generation):
        assert self.permits is False
        self.event('undo:' + step)
        self.resources.discard(step)
    def revoke_owned(self, generation):
        self.event('revoke')
        self.permits = False
    def verify_closed(self, generation):
        self.event('verify_closed')
        assert not self.permits
        return True


def transaction(adapter): return t.Transaction(adapter, 'a'*32, 'b'*64)


def test_success_never_admits_clients_and_cannot_be_reused():
    a = Adapter(); tx = transaction(a)
    result = tx.run()
    assert result['state'] == 'prepared_clients_closed'
    assert result['client_admission'] is False
    assert a.resources == set(t.STEPS)
    with pytest.raises(SafetyError): tx.run()
    with pytest.raises(SafetyError): tx.recover()


@pytest.mark.parametrize('step', t.STEPS)
def test_partial_mutation_is_recovered_in_reverse_order(step):
    a = Adapter('apply:' + step); tx = transaction(a)
    with pytest.raises(SafetyError, match='rolled back'): tx.run()
    assert a.resources <= {'close_clients'}
    assert a.journal['state'] == 'rolled_back_clients_closed'
    undone = [e[5:] for e in a.events if e.startswith('undo:')]
    expected = list(t.STEPS[:t.STEPS.index(step)+1])[::-1]
    assert undone == [e for e in expected if e != 'close_clients']
    assert a.events.index('revoke') < min(a.events.index('undo:' + e) for e in undone)


def test_foreign_collision_preflight_does_not_trigger_mutation_or_cleanup():
    a = Adapter('preflight')
    with pytest.raises(OSError): transaction(a).run()
    assert a.events == ['preflight']
    assert a.journal is None


def test_failed_final_commit_is_recovered():
    a = Adapter('save:prepared_clients_closed')
    with pytest.raises(SafetyError, match='rolled back'): transaction(a).run()
    assert a.resources == {'close_clients'}
    assert a.journal['state'] == 'rolled_back_clients_closed'


def interrupted(a):
    tx = transaction(a)
    tx.value['entries'] = [{'step': name, 'state': 'done'} for name in t.STEPS[:3]]
    tx.value['entries'][-1]['state'] = 'intent'
    a.resources = set(t.STEPS[:3]); a.permits = True
    tx.save()
    return t.Transaction.from_journal(a, a.journal)


def test_recover_durable_intent_after_interruption_without_reapplying():
    a = Adapter(); tx = interrupted(a)
    tx.recover()
    assert a.resources == {'close_clients'}
    assert not any(e.startswith('apply:') for e in a.events)


def test_rollback_ownership_failure_stops_dependent_cleanup_and_is_retryable():
    a = Adapter('undo:stage_protected_files'); tx = interrupted(a)
    with pytest.raises(OSError): tx.recover()
    assert a.journal['state'] == 'recovery_required'
    assert 'undo:inventory_backup' not in a.events
    t.Transaction.from_journal(a, a.journal).recover()
    assert a.journal['state'] == 'rolled_back_clients_closed'


@pytest.mark.parametrize('failure', ['revoke', 'verify_closed', 'save:recovering'])
def test_no_destructive_rollback_until_revocation_and_journal_are_confirmed(failure):
    a = Adapter(); tx = interrupted(a); a.failure = failure
    with pytest.raises(OSError): tx.recover()
    assert not any(e.startswith('undo:') for e in a.events)
    if failure == 'save:recovering': assert 'revoke' in a.events


@pytest.mark.parametrize('change', [
    {'client_admission': True}, {'schema': True}, {'state': []},
    {'generation': '../x'}, {'package_sha256': 'untrusted'},
    {'state': 'prepared_clients_closed'}, {'command': 'anything'},
    {'entries': [{'step': 'install_services', 'state': 'intent'}]},
    {'entries': [{'step': 'inventory_backup', 'state': []}]},
])
def test_untrusted_journal_cannot_select_operations(change):
    a = Adapter(); value = transaction(a).value
    with pytest.raises(SafetyError): t.Transaction.from_journal(a, {**value, **change})
    assert a.events == []


@pytest.mark.parametrize('result',[None,False,0,1,'true',{}])
def test_boundary_result_must_be_explicit_true_before_staging(result):
    a=Adapter();a.verify_closed=lambda generation:result
    with pytest.raises(SafetyError):transaction(a).run()
    assert not any(e.startswith('apply:stage') or e.startswith('apply:install') for e in a.events)
    assert not any(e.startswith('undo:') for e in a.events)


def test_lost_boundary_stops_recovery_before_next_resource():
    a=Adapter();tx=interrupted(a)
    real=a.undo
    def undo(step,generation):
        real(step,generation)
        a.verify_closed=lambda generation:False
    a.undo=undo
    with pytest.raises(SafetyError):tx.recover()
    assert 'undo:stage_protected_files' in a.events
    assert 'undo:inventory_backup' not in a.events
    assert a.journal['state']=='recovery_required'


@pytest.mark.parametrize('states',[
    ['undone','done'],['done','undone','intent'],['intent','done'],['intent','intent'],
])
def test_malformed_recovery_order_never_reaches_adapter(states):
    a=Adapter();value=transaction(a).value;value['state']='recovering'
    value['entries']=[dict(step=step,state=state) for step,state in zip(t.STEPS,states)]
    with pytest.raises(SafetyError):t.Transaction.from_journal(a,value)
    assert a.events==[]
