"""Build a fixed-capability Windows admin broker; never elevate or install it."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(argv):
    result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=60,
                            creationflags=0x08000000)
    if result.returncode:
        raise RuntimeError(result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))
    return result.stdout


def build(output):
    output = Path(output).resolve()
    if (output / 'build-receipt.json').exists():
        raise RuntimeError('Preserve the reviewed server. Choose a fresh output directory, or use --client-only.')
    output.mkdir(parents=True, exist_ok=True)
    compiler = Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    identity = json.loads(run([powershell, '-NoProfile', '-NonInteractive', '-Command',
        "@{sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;session=(Get-Process -Id $PID).SessionId}|ConvertTo-Json -Compress"]))
    if not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+', identity['sid']):
        raise RuntimeError('A concrete local/domain user SID is required')
    manifest = output / 'as-invoker.manifest'
    manifest.write_text('''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges>
<requestedExecutionLevel level="asInvoker" uiAccess="false"/>
</requestedPrivileges></security></trustInfo></assembly>''', encoding='utf-8')
    gateway = output / 'ClaudeResetGatewayFixture.exe'
    run([compiler, '/nologo', '/platform:x64', '/target:exe', '/define:FIXTURE',
         '/win32manifest:' + str(manifest), '/r:System.ServiceProcess.dll',
         '/r:System.Web.Extensions.dll', '/out:' + str(gateway), ROOT / 'src/native/ClaudeResetGateway.cs'])
    info = output / 'AdminBrokerBuildInfo.cs'
    info.write_text('static class AdminBuild { internal const string OwnerSid = "' + identity['sid'] +
                   '"; internal const int SessionId = ' + str(int(identity['session'])) +
                   '; internal const string GatewayHash = "' + sha(gateway) + '"; }\n', encoding='utf-8')
    exe = output / 'ClaudeResetAdminBroker.exe'
    common = [compiler, '/nologo', '/platform:x64', '/target:exe',
              '/win32manifest:' + str(manifest), '/r:System.ServiceProcess.dll', '/r:System.Web.Extensions.dll',
              '/resource:' + str(gateway) + ',GatewayFixture']
    sources = [info, ROOT / 'src/native/ClaudeResetAdminBroker.cs']
    run([*common, '/out:' + str(exe), *sources])
    tests = output / 'AdminBrokerTests.exe'
    run([*common, '/main:AdminBrokerTests', '/out:' + str(tests), *sources, ROOT / 'src/tests/native/AdminBrokerTests.cs'])
    result = json.loads(run([tests]))
    if not result.get('passed'):
        raise RuntimeError('Broker tests failed')
    receipt = {'schema': 1, 'helper_version': '0.1.1', 'owner_sid': identity['sid'],
               'windows_session': identity['session'], 'helper_sha256': sha(exe),
               'gateway_fixture_sha256': sha(gateway), 'tests': result,
               'files': {str(p.relative_to(ROOT)): sha(p) for p in
                         (ROOT / 'src/native/ClaudeResetAdminBroker.cs', ROOT / 'src/native/ClaudeResetGateway.cs',
                          ROOT / 'src/tests/native/AdminBrokerTests.cs', Path(__file__))},
               'elevated_live_acceptance': False, 'installed': False, 'uac_requested': False}
    (output / 'build-receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    build_client(output, receipt)
    return exe, receipt


def build_client(output, receipt):
    """Repair only the ordinary client; keep an already elevated server intact."""
    output = Path(output).resolve()
    exe = output / 'ClaudeResetAdminBroker.exe'
    gateway = output / 'ClaudeResetGatewayFixture.exe'
    if not re.fullmatch(r'[0-9a-f]{64}', receipt['helper_sha256']) or sha(exe) != receipt['helper_sha256']:
        raise RuntimeError('Reviewed server bytes changed')
    if sha(gateway) != receipt['gateway_fixture_sha256']:
        raise RuntimeError('Reviewed embedded fixture changed')
    if not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+', receipt['owner_sid']):
        raise RuntimeError('Invalid build identity')
    info = output / 'AdminClientBuildInfo.cs'
    info.write_text('static class AdminClientBuild { internal const string ServerHash = "' + receipt['helper_sha256'] + '"; }\n'
                    'static class AdminBuild { internal const string OwnerSid = "' + receipt['owner_sid'] + '"; '
                    'internal const int SessionId = ' + str(int(receipt['windows_session'])) + '; '
                    'internal const string GatewayHash = "' + receipt['gateway_fixture_sha256'] + '"; }\n', encoding='utf-8')
    compiler = Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    common = [compiler, '/nologo', '/platform:x64', '/target:exe',
              '/win32manifest:' + str(output / 'as-invoker.manifest'),
              '/r:System.ServiceProcess.dll', '/r:System.Web.Extensions.dll',
              '/resource:' + str(gateway) + ',GatewayFixture']
    sources = [info, ROOT / 'src/native/ClaudeResetAdminBroker.cs', ROOT / 'src/native/ClaudeResetAdminClient.cs']
    client = output / 'ClaudeResetAdminClient.exe'
    run([*common, '/main:ClaudeResetAdminClient', '/out:' + str(client), *sources])
    tests = output / 'AdminClientTests.exe'
    run([*common, '/main:AdminBrokerTests', '/out:' + str(tests), *sources, ROOT / 'src/tests/native/AdminBrokerTests.cs'])
    result = json.loads(run([tests]))
    if not result.get('passed') or not result.get('separate_process_disconnect_test'):
        raise RuntimeError('Client regression tests failed')
    repair = {'schema': 1, 'client_version': '0.1.1', 'client_sha256': sha(client),
              'pinned_server_sha256': receipt['helper_sha256'], 'tests': result,
              'elevated_server_changed': False, 'uac_requested': False,
              'files': {str(p.relative_to(ROOT)): sha(p) for p in
                        (ROOT / 'src/native/ClaudeResetAdminBroker.cs', ROOT / 'src/native/ClaudeResetAdminClient.cs',
                         ROOT / 'src/tests/native/AdminBrokerTests.cs', Path(__file__))}}
    (output / 'client-build-receipt.json').write_text(json.dumps(repair, indent=2), encoding='utf-8')
    return client, repair


def launchers(exe, receipt):
    # The elevated bootstrap is passed by value in EncodedCommand. It reads the
    # exact pinned payload as data, then starts only its protected copy.
    template = (ROOT / 'tools/admin_broker_launcher.ps1.in').read_text(encoding='utf-8')
    client = exe.with_name('ClaudeResetAdminClient.exe')
    values = {'@@SOURCE@@': str(exe).replace("'", "''"), '@@HASH@@': receipt['helper_sha256'],
              '@@CLIENT@@': str(client).replace("'", "''"), '@@CLIENT_HASH@@': sha(client),
              '@@SID@@': receipt['owner_sid']}
    for key, value in values.items():
        template = template.replace(key, value)
    destination = ROOT / 'Start-ClaudeResetAdmin.ps1'
    destination.write_text(template, encoding='utf-8-sig')
    (ROOT / 'Start-ClaudeResetAdmin.cmd').write_text(
        '@echo off\r\n"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" '
        '-NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-ClaudeResetAdmin.ps1"\r\n'
        'if errorlevel 1 pause\r\n', encoding='ascii')
    (ROOT / 'ClaudeResetAdmin.cmd').write_text(
        '@echo off\r\n"' + str(client) + '" --client "%~1"\r\n', encoding='ascii')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-root', type=Path, default=ROOT / 'work/admin-broker/v0.1.1')
    parser.add_argument('--client-only', action='store_true', help='Preserve reviewed server; pin repaired client to its build receipt')
    parser.add_argument('--emit-launchers', action='store_true')
    args = parser.parse_args()
    if args.client_only:
        receipt = json.loads((args.output_root / 'build-receipt.json').read_text(encoding='utf-8'))
        client, repair = build_client(args.output_root, receipt)
        exe = args.output_root.resolve() / 'ClaudeResetAdminBroker.exe'
    else:
        exe, receipt = build(args.output_root)
    if args.emit_launchers:
        launchers(exe, receipt)
    print(json.dumps({'exe': str(exe), 'sha256': receipt['helper_sha256'],
                      'tests': repair['tests'] if args.client_only else receipt['tests'], 'uac_requested': False}))
