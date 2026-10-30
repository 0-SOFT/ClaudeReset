import pytest

from claude_reset.network.isolation_audit import summarize
from claude_reset.safeio import SafetyError


@pytest.mark.parametrize('rows', [[], [{'scoped': True, 'appcontainer': False}],
                               [{'scoped': True, 'appcontainer': True, 'capability_count': 0}],
                               [{'scoped': True, 'token_read_failed': True}]])
def test_process_snapshot_and_no_vm_never_authorize_network(rows):
    result = summarize(rows, {'inventory_verified': True, 'running_guests': 0, 'guest_verified': False})
    assert result['passed'] is False and result['full_tunnel_verified'] is False
    assert result['cowork']['guest_verified'] is False


def test_audit_counts_escaped_child_separately():
    result = summarize([{'scoped': True, 'descendant': True, 'protected_identity': False, 'appcontainer': False},
                        {'scoped': False, 'appcontainer': False}], {})
    assert result['descendants_without_protected_identity'] == 1
    assert result['claude_processes_outside_protected_scope'] == 1


def test_unavailable_adapter_probe_does_not_become_zero_or_hide_identity_failure():
    from claude_reset.network import isolation_audit
    result = isolation_audit.local_metadata_probe(run_in=lambda *a: {
        'family': 'unrelated', 'location_status': 'unavailable', 'non_loopback_adapters': 'unavailable'})
    assert all(not row['identity_matches'] and row['non_loopback_adapters_visible'] is None for row in result['packages'])
    assert result['coordinates_requested'] is False and result['network_requests'] == 0
def test_cowork_service_outside_scope_is_visible_as_a_gap_not_absent():
    from claude_reset.network.isolation_audit import summarize
    result=summarize([{'kind':'cowork-svc.exe','scoped':False,'token_read_failed':True}],
                     {'inventory_verified':False,'guest_verified':False})
    assert result['cowork_service_observed']
    assert not result['cowork_service_within_protected_scope']
    assert not result['passed'] and not result['full_tunnel_verified']
