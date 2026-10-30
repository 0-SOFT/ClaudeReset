"""Contracts with code and data outside this commit.

The running backend worker imports claude_reset.windows.DPAPI from the source tree; installed tasks, UAC
relaunches and the VS Code wrapper call the command line; an installed older controller and a newer window
read each other's files and WFP filter keys. A refactoring must keep all of these byte-for-byte.

The expected values live in golden/live_contracts.json. Regenerate only for an intended contract change:
    UPDATE_LIVE_CONTRACTS=1 python -m pytest tests/test_live_contracts.py
"""
import argparse
import ast
import importlib
import json
import os
from pathlib import Path
import types

import pytest

from claude_reset.backend import profiles as backend_profiles, gateway_profile
from claude_reset.network import connections, gateway_reservation, l1_consent, l1_install
from claude_reset.network import remote_backend, strict_wfp
from claude_reset.windows import wfp
from claude_reset.backend.attestation import inspect_sing_box
from test_backend_attestation import config as sing_box_config
from test_gateway_profile import profile as gateway_sample
from test_l1_install import Fake, state

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = Path(__file__).with_name('golden') / 'live_contracts.json'
UPDATE = os.environ.get('UPDATE_LIVE_CONTRACTS') == '1'


def golden(section, value):
    stored = json.loads(GOLDEN.read_text('utf-8')) if GOLDEN.exists() else {}
    value = json.loads(json.dumps(value))
    if UPDATE:
        stored[section] = value
        GOLDEN.parent.mkdir(exist_ok=True)
        GOLDEN.write_text(json.dumps(stored, indent=1, ensure_ascii=False, sort_keys=True) + '\n', 'utf-8')
    assert section in stored, f'no golden value for {section}; see the module docstring'
    assert value == stored[section]


def test_backend_worker_imports_dpapi_from_the_source_tree():
    # packaging/backend/proxy_worker.py and every worker installed from it.
    from claude_reset.windows.system import DPAPI
    assert callable(DPAPI().encrypt) and callable(DPAPI().decrypt)


def script_imports():
    scripts = [*ROOT.glob('tools/*.py'), *ROOT.glob('packaging/**/*.py'), *(ROOT / 'src').glob('*.py')]
    found = set()
    for script in scripts:
        for node in ast.walk(ast.parse(script.read_text('utf-8', errors='replace'))):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith('claude_reset') and not node.level:
                found.update((node.module, alias.name) for alias in node.names)
            elif isinstance(node, ast.Import):
                found.update((alias.name, None) for alias in node.names if alias.name.startswith('claude_reset'))
    return sorted(found, key=lambda pair: (pair[0], pair[1] or ''))


@pytest.mark.parametrize('module,name', script_imports())
def test_names_imported_by_tools_and_entry_scripts_exist(module, name):
    imported = importlib.import_module(module)
    if name is not None:
        assert hasattr(imported, name) or importlib.util.find_spec(f'{module}.{name}') is not None


def command_line_parser(monkeypatch):
    from claude_reset.ui import expert_window as app
    from claude_reset import cli

    class Captured(Exception):
        pass

    def capture(parser, *args, **kwargs):
        raise Captured(parser)
    monkeypatch.setattr(argparse.ArgumentParser, 'parse_args', capture)
    with pytest.raises(Captured) as caught:
        cli.main([])
    return caught.value.args[0]


def test_command_line_surface_is_unchanged(monkeypatch):
    parser = command_line_parser(monkeypatch)
    options = []
    for action in parser._actions:
        options.append({'options': sorted(action.option_strings), 'dest': action.dest, 'action': type(action).__name__,
                        'nargs': action.nargs, 'const': repr(action.const), 'default': repr(action.default),
                        'choices': sorted(action.choices) if action.choices else None,
                        'type': getattr(action.type, '__name__', None), 'hidden': action.help == argparse.SUPPRESS})
    groups = [sorted(a.dest for a in group._group_actions) for group in parser._mutually_exclusive_groups]
    golden('command_line', {'options': sorted(options, key=lambda o: o['dest']), 'exclusive_groups': sorted(groups)})


def test_wfp_filter_keys_are_unchanged():
    package = strict_wfp.Identity('package', 'Claude_pzs8sxrjxfjjc')
    owned = strict_wfp.Identity('package', 'ClaudeReset.NetworkIsolation_79st3xwgefr0c')
    app_path = strict_wfp.Identity('app', 'C:\\Users\\person\\.local\\bin\\claude.exe')
    identities = [package, owned, app_path]
    engine = strict_wfp.Identity('app', 'C:\\Program Files\\ClaudeReset\\Engine\\engine.exe')
    golden('wfp_keys', {
        'strict_sublayer': strict_wfp.SUBKEY.value(),
        'strict_layers': {name: guid.value() for name, guid in sorted(strict_wfp.LAYERS.items())},
        'deny': [rule.key.value() for rule in strict_wfp.deny_rules(identities)],
        'relay': [rule.key.value() for rule in strict_wfp.relay_permits(identities, 25082)],
        'pinned_endpoint': strict_wfp.Rule(engine, 'connect_v4', strict_wfp.PERMIT, '198.51.100.7', 443).key.value(),
        'service_endpoints': [strict_wfp.ServiceRule(engine, layer, strict_wfp.PERMIT, '127.0.0.1', 25080, True, service).key.value()
                              for service in ('ClaudeResetBackend', 'ClaudeResetGateway') for layer in ('connect_v4', 'recv_v4')],
        'gateway_sublayer': gateway_reservation.SUB.value(),
        'gateway_namespace': str(gateway_reservation.NS),
        'owned_filters': [[f.group, f.target, f.family, f.key, f.sublayer, f.mark.decode(), f.kind, f.package_family]
                          for f in wfp.OWNED_FILTERS],
    })


def test_stored_document_formats_are_unchanged():
    connection = connections.validate({'schema': 1, 'local_proxy': 'http://127.0.0.1:25080', 'router_proxy': None,
                                       'expected_exit_ips': ['1.1.1.1', '2606:4700:4700::1111']})
    profile = {'schema': 1, 'adapter': 'sing_box_vless_reality_v1', 'engine_path': 'C:\\Runtime\\engine.exe',
               'engine_sha256': 'a' * 64, 'engine_version': '1.12.0', 'config': sing_box_config()}
    socks = {'schema': 1, 'adapter': 'socks5_remote_v1', 'host': '1.1.1.1', 'port': 1080, 'username': 'user', 'password': 'secret'}
    decoded_socks = remote_backend.decode(json.dumps(socks).encode())
    coverage = {'status': l1_consent.STATUS, 'remaining_boundaries': ['cowork_guest_boundary', 'mcp_children'], 'dns': {'passed': False}}
    golden('documents', {
        'connection_saved_bytes': json.dumps(connection),
        'backend_profile': backend_profiles.decode(json.dumps(profile).encode()),
        'backend_summary': backend_profiles.summary('profile-id', profile),
        'sing_box_inspection': inspect_sing_box(sing_box_config()),
        'remote_backend': decoded_socks,
        'remote_backend_kind': remote_backend.backend_kind(decoded_socks),
        'gateway_profile_bytes': gateway_profile.encode(gateway_profile.validate(gateway_sample())).decode('utf-8'),
        'consent_required': l1_consent.required(coverage),
        'consent_file': l1_consent.FILE,
    })


@pytest.mark.parametrize('scenario', ['installed', 'needs_consent', 'package_failed'])
def test_protection_install_report_shape_is_unchanged(tmp_path, scenario):
    paths = types.SimpleNamespace(home=tmp_path, state=tmp_path / 'state', local=tmp_path / 'local')
    fake = Fake(package=scenario == 'package_failed')
    report = l1_install.run(paths, deps=fake, build_dir=Path('b'), confirmed=scenario != 'needs_consent')
    from claude_reset.ui import expert_window as app
    from claude_reset import cli
    golden(f'l1_install_report_{scenario}', {'report': cli.explain_next(report), 'calls': fake.calls})


def test_protection_install_initial_state_fixture_is_stable():
    # The reports above depend on this fixture; a change to it must be deliberate.
    golden('l1_install_fixture_state', state())
