import pytest
from claude_reset.backend.lifecycle import Generation
from claude_reset.safeio import SafetyError


class Resource:
    def __init__(self, platform, name): self.platform, self.name = platform, name
    def close(self): self.platform.step('close_' + self.name)
    def resume(self): self.platform.step('resume')


class Platform:
    def __init__(self, fail=None): self.events = []; self.fail = fail; self.probe_result = True
    def step(self, name):
        self.events.append(name)
        if name == self.fail: raise SafetyError('fixture')
    def prepare(self): self.step('prepare')
    def suspended_engine(self): self.step('suspended'); return Resource(self, 'child')
    def acquire_lease(self): self.step('lease'); return Resource(self, 'lease')
    def verify_boundary(self, lease): self.step('boundary')
    def start_gateway(self, child): self.step('gateway'); return Resource(self, 'gateway')
    def verify_generation(self, child, gateway, lease): self.step('generation')
    def probe(self): self.step('probe'); return self.probe_result
    def close(self): self.step('close_platform')


def test_generation_never_admits_clients_and_revokes_before_stopping():
    platform = Platform(); generation = Generation(platform)
    status = generation.start()
    assert status['state'] == 'BACKEND_VERIFIED_CLIENTS_CLOSED'
    assert not status['client_admission'] and not status['full_tunnel_verified']
    assert platform.events == ['prepare','suspended','lease','boundary','resume','gateway','generation','probe','generation']
    generation.poll(); generation.close(); generation.close()
    assert platform.events[-4:] == ['close_lease','close_child','close_gateway','close_platform']
    with pytest.raises(SafetyError): generation.start()


@pytest.mark.parametrize('failure', ['prepare','suspended','lease','boundary','resume','gateway','generation','probe'])
def test_every_start_failure_closes_owned_resources(failure):
    platform = Platform(failure); generation = Generation(platform)
    with pytest.raises(SafetyError): generation.start()
    assert generation.closed and generation.state == 'BLOCKED'
    assert platform.events[-1] == 'close_platform'
    cleanup = [event for event in platform.events if event.startswith('close_')]
    assert cleanup == [name for name in ['close_lease','close_child','close_gateway','close_platform'] if name in cleanup]


def test_exit_mismatch_and_later_generation_drift_are_fatal():
    platform = Platform(); platform.probe_result = False; generation = Generation(platform)
    with pytest.raises(SafetyError): generation.start()
    assert generation.closed
    platform = Platform(); generation = Generation(platform); generation.start()
    platform.fail = 'generation'
    with pytest.raises(SafetyError): generation.poll()
    assert generation.closed and generation.state == 'BLOCKED'


@pytest.mark.parametrize('failure', ['close_lease','close_child','close_gateway','close_platform'])
def test_cleanup_failure_does_not_skip_remaining_owned_resources(failure):
    platform = Platform(); generation = Generation(platform); generation.start(); platform.fail = failure
    with pytest.raises(SafetyError): generation.close()
    assert platform.events[-4:] == ['close_lease','close_child','close_gateway','close_platform']
    assert generation.state == 'BLOCKED_CLEANUP_UNCONFIRMED'
