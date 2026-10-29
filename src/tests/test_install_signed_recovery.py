"""Real CNG signatures and protected temp files; all SCM/WFP effects modeled."""
import pytest
from test_install_runtime_signature import signed
from test_install_attested_cleanup import setup,cleanup
from test_install_removal_confirmation import prepare
from claude_reset.install_recovery_inputs import RecoveryInputs
from claude_reset.install_removal_confirmation import confirm_recorded_removal
from claude_reset.safeio import SafetyError


def test_signed_runtime_can_complete_attested_service_cleanup(tmp_path,monkeypatch,signed):
    with setup(tmp_path,monkeypatch,signed=signed) as fixture:
        step,inputs,held,native,*_=fixture
        assert inputs.report()['runtime_signature_files']==11
        result=cleanup(fixture).run()
        assert result['absence_verified'] is True and result['client_admission'] is False
        assert len(native.deleted)==4 and held.closed
        assert inputs.report()['runtime_signature_files']==11


def test_signed_runtime_can_confirm_pending_service_removal(tmp_path,monkeypatch,signed):
    with setup(tmp_path,monkeypatch,signed=signed) as fixture:
        step=fixture[0];prepare(fixture,monkeypatch)
        with RecoveryInputs(step.store,step.generation) as inputs:
            result=confirm_recorded_removal(step.store,inputs,step.generation,lambda g:True)
            assert result['absence_verified'] is True and result['deletion_replayed'] is False
            assert inputs.report()['runtime_signature_files']==11


def test_closed_signature_pin_stops_cleanup_before_service_deletion(tmp_path,monkeypatch,signed):
    with setup(tmp_path,monkeypatch,signed=signed) as fixture:
        inputs,native=fixture[1],fixture[3]
        next(iter(inputs.runtime_signatures.pins.values())).close()
        with pytest.raises(SafetyError):cleanup(fixture).run()
        assert native.deleted==[]


def test_signed_runtime_reconciles_remaining_services(tmp_path,monkeypatch,signed):
    from test_install_reconciled_cleanup import setup as remaining,operation
    with remaining(tmp_path,monkeypatch,2,signed=signed) as fixture:
        with fixture[-1]() as held:
            result=operation(fixture,held).run()
        assert result['services_absent']==4 and result['new_deletion_requests']==2
        assert result['client_admission'] is False


def test_signed_runtime_reconciles_pending_creation(tmp_path,monkeypatch,signed):
    from test_install_creation_cleanup import setup as pending,operation
    with pending(tmp_path,monkeypatch,signed=signed) as fixture:
        result=operation(fixture).run()
        assert result['client_admission'] is False


def test_signed_runtime_reconciles_listener_reservations(tmp_path,monkeypatch,signed):
    from test_install_reservation_confirmation import fixture as reservations
    from test_install_reservation_reconciliation import run
    with reservations(tmp_path,monkeypatch,True,'committed',signed=signed) as fixture:
        result=run(fixture,monkeypatch)
        assert result['reservations_absent'] is True and result['new_removal_transaction'] is True
        assert result['client_admission'] is False


def test_signed_runtime_reconciles_initial_boundary(tmp_path,monkeypatch,signed):
    from test_install_boundary_reconciliation import fixture as boundary,run
    with boundary(tmp_path,monkeypatch,True,signed=signed) as fixture:
        result=run(fixture)
        assert result['client_admission'] is False
