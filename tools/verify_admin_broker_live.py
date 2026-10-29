"""Validate an owner-started helper without another elevation or client network access.

Read WFP/HCS and create/delete only the broker's stopped fixture registration.
Never start the fixture, stop applications, or change firewall/network settings.
"""
from pathlib import Path
import argparse
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import json
import hashlib
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'work/admin-broker/v0.1.0'
EXE = BASE / 'ClaudeResetAdminClient.exe'


def call(operation):
    p = subprocess.run([str(EXE), '--client', operation], capture_output=True,
                       timeout=35, creationflags=0x08000000)
    if p.returncode:
        raise RuntimeError(operation + ': ' + p.stderr.decode(errors='replace') + p.stdout.decode(errors='replace'))
    data = json.loads(p.stdout)
    if not data.get('ok'):
        raise RuntimeError('Helper rejected operation: ' + operation)
    return data['result']


def denied_handle(path, desired, directory=False):
    kernel = C.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p, W.DWORD, W.DWORD, W.HANDLE]
    kernel.CreateFileW.restype = W.HANDLE
    kernel.CloseHandle.argtypes = [W.HANDLE]
    value = kernel.CreateFileW(str(path), desired, 7, None, 3, 0x02000000 if directory else 0, None)
    if value == C.c_void_p(-1).value:
        return {'denied': C.get_last_error() == 5, 'winerror': C.get_last_error()}
    kernel.CloseHandle(value)
    return {'denied': False, 'winerror': 0}  # No write, ACL change or deletion was performed.


def main():
    report = {'schema': 1, 'utc': datetime.now(timezone.utc).isoformat(), 'passed': False,
              'uac_requested': False, 'network_changed': False, 'clients_launched': False,
              'fixture_started': False, 'driver_installed': False}
    attempted = False
    try:
        client_receipt = json.loads((BASE / 'client-build-receipt.json').read_text(encoding='utf-8'))
        report['client_sha256'] = hashlib.sha256(EXE.read_bytes()).hexdigest()
        assert report['client_sha256'] == client_receipt['client_sha256'], 'Client build differs'
        report['pinned_server_sha256'] = client_receipt['pinned_server_sha256']
        report['status'] = call('status')
        assert report['status']['elevated'] and not report['status']['arbitrary_commands_supported']
        assert not report['status']['driver_install_supported'] and not report['status']['production_clients_permitted']
        report['services_before'] = call('services')
        report['wfp'] = call('wfp')
        report['hcs'] = call('hcs')
        # Resolve the fixed protected root using Windows, not caller input.
        shell = C.WinDLL('shell32')
        shell.SHGetFolderPathW.argtypes = [W.HWND, C.c_int, W.HANDLE, W.DWORD, W.LPWSTR]
        buffer = C.create_unicode_buffer(260)
        if shell.SHGetFolderPathW(None, 0x26, None, 0, buffer):
            raise RuntimeError('Program Files unavailable')
        protected = Path(buffer.value) / 'ClaudeResetAdmin'
        active = json.loads((protected / 'active.json').read_text(encoding='utf-8'))
        assert active['sha256'] == report['pinned_server_sha256'], 'Server differs'
        report['session'] = active['session']
        report['expires_utc'] = active['expires_utc']
        checks = []
        for path, directory in [(protected, True), (Path(active['image']), False), (protected / 'active.json', False)]:
            for access in (2, 0x40000, 0x80000, 0x10000):
                checks.append(dict(target=path.name, access=access, **denied_handle(path, access, directory)))
        report['ordinary_mutation_handles'] = checks
        assert all(row['denied'] for row in checks), 'Unprivileged client obtained mutation rights'
        existing = [s for s in report['services_before']['services']
                    if s['name'] == 'ClaudeResetGatewayFixture' and s['installed']]
        if existing:
            raise RuntimeError('Pre-existing fixture: not modified')
        report['stage'] = call('stage-fixture')
        attempted = True
        report['register'] = call('register-fixture')
        services = call('services')
        fixture = next(s for s in services['services'] if s['name'] == 'ClaudeResetGatewayFixture')
        assert fixture['installed'] and fixture['state'] == 'Stopped'
        report['registered_state'] = fixture
        report['remove'] = call('remove-fixture')
        report['services_after'] = call('services')
        assert not next(s for s in report['services_after']['services'] if s['name'] == 'ClaudeResetGatewayFixture')['installed']
        report['fixture_cleanup_completed'] = True
        # HCS failure is not silently promoted to successful elevated acceptance.
        assert report['hcs'].get('inventory_verified'), 'HCS inventory incomplete'
        report['passed'] = True
    except Exception as exc:
        report['error'] = str(exc)
    finally:
        if attempted and not report.get('fixture_cleanup_completed'):
            try:
                report['cleanup'] = call('remove-fixture')
                report['fixture_cleanup_completed'] = True
            except Exception as exc:
                report['cleanup_error'] = str(exc)
        (BASE / 'live-acceptance.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'passed': report['passed'], 'evidence': str(BASE / 'live-acceptance.json'),
                      'fixture_cleanup_completed': report.get('fixture_cleanup_completed', False),
                      'error': report.get('error')}, ensure_ascii=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--broker-root', type=Path, default=BASE)
    BASE = parser.parse_args().broker_root.resolve()
    EXE = BASE / 'ClaudeResetAdminClient.exe'
    raise SystemExit(main())
