import pytest

from claude_reset.network import l1_consent as consent
from claude_reset.safeio import SafetyError


def coverage(extra=(), dns=False, status=consent.STATUS):
    return {'passed': False, 'status': status, 'dns': {'passed': dns},
            'remaining_boundaries': ['complete_ipc_boundary', 'cowork_guest_boundary', *extra]}


def test_no_consent_keeps_relay_closed():
    assert not consent.admits(coverage(), None)


def test_consent_covers_exactly_the_open_boundaries(tmp_path):
    saved = consent.record(tmp_path, coverage())
    assert consent.DNS in saved['accepted'] and 'cowork_guest_boundary' in saved['accepted']
    assert consent.admits(coverage(), consent.load(tmp_path))


def test_new_boundary_after_consent_closes_again(tmp_path):
    consent.record(tmp_path, coverage())
    assert not consent.admits(coverage(extra=('new_unreviewed_channel',)), consent.load(tmp_path))


def test_dns_contained_needs_no_dns_consent(tmp_path):
    saved = consent.record(tmp_path, coverage(dns=True))
    assert consent.DNS not in saved['accepted']
    assert consent.admits(coverage(dns=True), consent.load(tmp_path))


@pytest.mark.parametrize('bad', [{}, {'status': 'other'}, {'status': consent.STATUS}, {'status': consent.STATUS, 'remaining_boundaries': 'x'}])
def test_unrecognised_coverage_is_never_admitted(tmp_path, bad):
    consent.record(tmp_path, coverage())
    assert not consent.admits(dict(passed=False, **bad), consent.load(tmp_path))
    with pytest.raises(SafetyError):
        consent.record(tmp_path, dict(passed=False, **bad))


def test_revoke_and_corrupt_file(tmp_path):
    consent.record(tmp_path, coverage())
    assert consent.revoke(tmp_path) and consent.load(tmp_path) is None
    (tmp_path / consent.FILE).write_bytes(b'junk')
    assert consent.load(tmp_path) is None


def test_passed_coverage_needs_no_consent():
    assert consent.admits({'passed': True}, None)
