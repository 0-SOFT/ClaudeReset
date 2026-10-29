"""Compile the fixed-capability helper and exercise actual local IPC without UAC."""
import importlib.util
import os
from pathlib import Path
import pytest


@pytest.mark.skipif(os.name != 'nt', reason='Windows named pipes and ACLs')
def test_admin_broker_local_transport_and_rejection(tmp_path):
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location('build_admin_broker', root / 'tools/build_admin_broker.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    exe, receipt = module.build(tmp_path)
    assert exe.is_file()
    assert receipt['tests']['passed'] and receipt['tests']['checks'] >= 40
    assert receipt['tests']['real_local_pipe_test']
    assert receipt['tests']['separate_process_disconnect_test']
    assert receipt['tests']['legacy_loss_reproduced']
    assert (tmp_path / 'ClaudeResetAdminClient.exe').is_file()
    assert not receipt['tests']['admin_mutations_executed']
    assert not receipt['uac_requested'] and not receipt['installed']
