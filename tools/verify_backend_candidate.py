"""Exercise inactive profile import with real DPAPI and source/frozen CLI, offline."""
import hashlib
import argparse
import json
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from claude_reset.windows.system import DPAPI


def main(candidate=None):
    base = ROOT / 'work/release-execution-2026-10-26'
    fixture = base / ('backend-fixture-' + uuid.uuid4().hex)
    fixture.mkdir()
    profile = {'schema': 1, 'adapter': 'sing_box_vless_reality_v1',
        'engine_path': str(fixture / 'not-executed.exe'), 'engine_sha256': 'a' * 64, 'engine_version': '1.12.0',
        'config': {'log': {'disabled': True},
            'inbounds': [{'type': 'socks', 'tag': 'fixture-in', 'listen': '127.0.0.1', 'listen_port': 1080}],
            'outbounds': [{'type': 'vless', 'tag': 'fixture-out', 'server': '1.1.1.1', 'server_port': 443,
                'uuid': '12345678-1234-1234-1234-123456789abc',
                'tls': {'enabled': True, 'server_name': 'fixture.invalid',
                    'utls': {'enabled': True, 'fingerprint': 'chrome'},
                    'reality': {'enabled': True, 'public_key': 'A' * 43, 'short_id': 'aabb'}}}],
            'route': {'final': 'fixture-out'}}}
    file = fixture / 'synthetic-profile.json'
    file.write_text(json.dumps(profile), encoding='utf-8')
    exe = candidate.resolve() if candidate else base / 'candidate/dist/ClaudeResetCandidate.exe'
    source = [sys.executable, str(ROOT / 'src/launcher.py')]
    frozen = [str(exe)]
    def call(command, *args):
        result = subprocess.run([*command, '--state-root', str(fixture), *args],
            capture_output=True, timeout=30, creationflags=0x08000000)
        assert result.returncode == 0, result.stderr.decode(errors='replace')
        return json.loads(result.stdout)
    reports = []
    for importer, reader in ((source, frozen), (frozen, source)):
        report = call(importer, '--backend-import', str(file))
        assert report == call(reader, '--backend-status', report['profile_id'])
        inventory=call(reader,'--backend-list')
        assert any(row==report for row in inventory['profiles']) and inventory['client_admission'] is False
        assert not any(report[k] for k in ('selected', 'client_network_opened', 'runtime_engine_verified', 'engine_build_verified'))
        encrypted = (fixture / 'backend-profiles' / (report['profile_id'] + '.dpapi')).read_bytes()
        assert b'12345678-1234' not in encrypted and b'fixture.invalid' not in encrypted
        assert json.loads(DPAPI().decrypt(encrypted)) == profile
        assert all(marker not in json.dumps(report) for marker in ('12345678-1234', 'fixture.invalid', '1.1.1.1'))
        reports.append(report)
    assert reports[0]['profile_id'] != reports[1]['profile_id']
    result = {'schema': 1, 'passed': True, 'actual_dpapi': True, 'source_frozen_bidirectional': True,
        'synthetic_only': True, 'clients_started': False, 'network_settings_changed': False,
        'candidate_sha256': hashlib.sha256(exe.read_bytes()).hexdigest(),
        'limits': ['Inactive import only; installed engine and tunnel admission remain unverified.']}
    # Store inside the unique fixture so repeated candidates retain their proof.
    (fixture / 'verification.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    result['fixture']=str(fixture)
    print(json.dumps(result))


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--candidate',type=Path)
    main(parser.parse_args().candidate)
