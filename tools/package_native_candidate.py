"""Collect compiled hardening outputs for review/signing; never install or load."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from claude_reset.windows import ps_json
from claude_reset.safeio import guarded


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def machine(path):
    data = path.read_bytes()
    if data[:2] != b'MZ': raise RuntimeError('Missing executable header')
    offset = struct.unpack_from('<I', data, 60)[0]
    if data[offset:offset+4] != b'PE\0\0': raise RuntimeError('Missing PE header')
    return struct.unpack_from('<H', data, offset+4)[0]


def runtime_trust_evidence(combined, expected, receipt):
    """Retain optional public-key provenance without treating it as authority."""
    from prepare_runtime_trust import RELATIVE, SERVICE_RELATIVE, validate_public_key
    names = (RELATIVE, SERVICE_RELATIVE)
    changes = receipt['changes']
    present = [name for name in names if changes.get(name, {}).get('layer') == 'runtime-trust']
    if not present:
        if receipt.get('runtime_public_key_sha256') is not None:
            raise RuntimeError('Runtime key declared without both verifier sources')
        return [], None
    if set(present) != set(names):
        raise RuntimeError('Runtime trust must bind driver and service together')
    folder = combined / 'runtime-trust'
    with (folder / 'manifest.json').open('rb') as stream: raw = stream.read(65537)
    if len(raw) > 65536: raise RuntimeError('Runtime trust metadata exceeds its bound')
    metadata = json.loads(raw)
    fields = {'schema', 'upstream_sha256', 'prepared_sha256', 'public_key_sha256',
              'service_upstream_sha256', 'service_prepared_sha256', 'service_runtime_key_matches_driver',
              'upstream_certificate_trust_changed', 'key_authority_verified', 'runtime_signatures_supplied',
              'windows_driver_signing_complete', 'installed', 'production_clients_permitted'}
    if (not isinstance(metadata, dict) or set(metadata) != fields
            or type(metadata['schema']) is not int or metadata['schema'] != 1
            or any(metadata[field] is not False for field in ('runtime_signatures_supplied',
                'windows_driver_signing_complete', 'installed', 'production_clients_permitted'))):
        raise RuntimeError('Exact unsigned runtime-trust preparation metadata required')
    public = folder / 'runtime-public-key.blob'
    with public.open('rb') as stream: blob = stream.read(73)
    validate_public_key(blob)
    digest = hashlib.sha256(blob).hexdigest()
    if (metadata.get('public_key_sha256') != digest
            or receipt.get('runtime_public_key_sha256') != digest
            or metadata.get('service_runtime_key_matches_driver') is not True
            or metadata.get('upstream_certificate_trust_changed') is not False
            or metadata.get('key_authority_verified') is not False
            or receipt.get('runtime_key_authority_verified') is not False):
        raise RuntimeError('Runtime public-key provenance differs or claims unreviewed authority')
    for name, field in zip(names, ('prepared_sha256', 'service_prepared_sha256')):
        if (metadata.get(field) != expected.get(name)
                or changes[name].get('prepared_sha256') != expected.get(name)
                or sha(folder / 'prepared' / name) != expected.get(name)):
            raise RuntimeError('Runtime verifier evidence differs from compiled sources')
        text = (folder / 'prepared' / name).read_text(encoding='utf-8')
        arrays = re.findall(r'static(?: const)? UCHAR CrRuntimePublicKey\[\]\s*=\s*\{([^}]+)\};', text)
        if len(arrays) != 1:
            raise RuntimeError('Exactly one generated runtime key is required per verifier')
        values = [value.strip() for value in arrays[0].strip().removesuffix(',').split(',')]
        if (len(values) != 72 or any(re.fullmatch(r'0x[0-9A-Fa-f]{2}', value) is None for value in values)
                or bytes(int(value, 16) for value in values) != blob):
            raise RuntimeError('Verifier embeds a different runtime public key')
    return [folder / 'manifest.json', public], digest


def broker_classification_evidence(combined, expected):
    names=('Sandboxie/core/svc/CrBrokerWindows.h','Sandboxie/core/drv/CrBrokerQuery.h',
           'Sandboxie/core/drv/process_api.c')
    if names[1] not in expected:return []
    path=combined/'broker-classification/result.json'
    result=json.loads(path.read_text(encoding='utf-8'))
    if (any(type(result.get(k)) is not int or result[k]!=v for k,v in
            [('service_cases',90),('driver_cases',72),('negative_controls',3)])
            or result.get('source_sha256')!={n:expected.get(n) for n in names}
            or result.get('test_sha256')!=sha(ROOT/'src/tests/native/BrokerClassificationTests.cpp')
            or any(result.get(k) is not False for k in
                ('installed','production_clients_permitted','loaded_driver_verified'))):
        raise RuntimeError('Matching broker classification evidence required')
    return [path]


def queue_event_evidence(combined, expected):
    name='Sandboxie/core/svc/queueserver.cpp'
    if name not in expected:return []
    source=combined/'source'/name
    if 'queue takes ownership only after reply allocation' not in source.read_text(encoding='utf-8'):return []
    path=combined/'service/queue-event-ownership/result.json'
    result=json.loads(path.read_text(encoding='utf-8'))
    if (type(result.get('cases')) is not int or result['cases']!=4
            or type(result.get('original_negative_controls')) is not int or result['original_negative_controls']!=4
            or type(result.get('request_id_boundary_checks')) is not int or result['request_id_boundary_checks']!=4
            or type(result.get('request_id_collision_checks')) is not int or result['request_id_collision_checks']!=6
            or type(result.get('process_lifetime_checks')) is not int or result['process_lifetime_checks']!=4
            or result.get('prepared_source_sha256')!=expected[name]
            or result.get('test_sha256')!=sha(ROOT/'src/tests/native/QueueEventOwnershipTests.cpp')
            or result.get('passed') is not True or result.get('api_stubs') is not True
            or result.get('installed_service_test') is not False
            or result.get('real_allocation_failure_injected') is not False):
        raise RuntimeError('Matching queue event ownership evidence required')
    return [path]


def queue_reply_evidence(combined, expected):
    name='Sandboxie/core/svc/queueserver.cpp'
    if name not in expected:return []
    source=combined/'source'/name
    if 'Preserve the first reply until the client consumes it.' not in source.read_text(encoding='utf-8'):return []
    path=combined/'service/queue-reply-ownership/result.json'
    result=json.loads(path.read_text(encoding='utf-8'))
    required={'cases':6,'original_negative_controls':1,'passed':True,'api_stubs':True,'installed_service_test':False}
    if (any(type(result.get(k)) is not type(v) or result[k]!=v for k,v in required.items())
            or result.get('prepared_source_sha256')!=expected[name]
            or result.get('test_sha256')!=sha(ROOT/'src/tests/native/QueueReplyOwnershipTests.cpp')):
        raise RuntimeError('Matching queue reply ownership evidence required')
    return [path]


def queue_lifecycle_evidence(combined, expected):
    name='Sandboxie/core/svc/queueserver.cpp'
    if name not in expected:return []
    source=combined/'source'/name
    if 'A premature fetch must not release the active worker identity.' not in source.read_text(encoding='utf-8'):return []
    path=combined/'service/queue-request-lifecycle/result.json'
    result=json.loads(path.read_text(encoding='utf-8'))
    required={'cases':10,'original_negative_controls':1,'passed':True,'api_stubs':True,'installed_service_test':False}
    if (any(type(result.get(k)) is not type(v) or result[k]!=v for k,v in required.items())
            or result.get('prepared_source_sha256')!=expected[name]
            or result.get('test_sha256')!=sha(ROOT/'src/tests/native/QueueRequestLifecycleTests.cpp')):
        raise RuntimeError('Matching queue request lifecycle evidence required')
    return [path]


def service_boundary_evidence(combined, expected):
    """Keep dispatch and real Windows handle checks bound to compiled sources."""
    if 'Sandboxie/core/svc/CrBootstrapSecurity.h' not in expected:return []
    folder=combined/'service'
    manifest=json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
    sources={'Sandboxie/core/svc/'+name:row['prepared_sha256']
             for name,row in manifest['files'].items()}
    if not sources or any(expected.get(name)!=digest for name,digest in sources.items()):
        raise RuntimeError('Service evidence manifest differs from compiled sources')
    cases=(
        ('native-dispatch-result.json','BrokerDispatchTests.cpp',
         {'assertions':474,'passed':True,'installed_service_test':False,
          'full_service_build_verified':False,'production_clients_permitted':False,'full_tunnel_verified':False}),
        ('windows-handle-transfer-result.json','HandleTransferWindowsTests.cpp',
         {'passed':True,'process_access':1052672,'thread_access':1050624,'child_exited':True,
          'identity_predicates_stubbed':True,'installed_service_test':False,
          'production_clients_permitted':False,'full_tunnel_verified':False}),
        ('windows-bootstrap-security-result.json','BootstrapSecurityWindowsTests.cpp',
         {'passed':True,'checks':33,'before_first_instruction':True,'future_threads_verified':False,
          'create_process_as_user_verified':False,'caller_environment_excluded':True,
          'production_clients_permitted':False}))
    paths=[folder/'manifest.json']
    for name,fixture,required in cases:
        path=folder/name
        result=json.loads(path.read_text(encoding='utf-8'))
        if (any(type(result.get(k)) is not type(v) or result[k]!=v for k,v in required.items())
                or result.get('service_source_sha256')!=sources
                or result.get('test_sha256')!=sha(ROOT/'src/tests/native'/fixture)):
            raise RuntimeError('Matching service boundary evidence required: '+name)
        paths.append(path)
    return paths


def main(combined, output, *, kit_root=None):
    combined, output = combined.resolve(), output.resolve()
    if output.exists(): raise RuntimeError('Candidate preserved; choose a fresh output directory')
    source = combined / 'source'
    expected = json.loads((combined / 'source-manifest.json').read_text())
    for relative, digest in expected.items():
        if sha(guarded(source / relative, source)) != digest:
            raise RuntimeError('Reviewed source changed: ' + relative)
    queue_evidence=queue_event_evidence(combined,expected)
    reply_evidence=queue_reply_evidence(combined,expected)
    queue_lifecycle=queue_lifecycle_evidence(combined,expected)
    classification_evidence=broker_classification_evidence(combined,expected)
    service_evidence=service_boundary_evidence(combined,expected)
    lifecycle_evidence=[]
    combined_receipt=json.loads((combined/'combined-receipt.json').read_text())
    changes=combined_receipt['changes']
    trust_evidence, runtime_key = runtime_trust_evidence(combined, expected, combined_receipt)
    managed=combined/'managed-config'
    managed_manifest=json.loads((managed/'manifest.json').read_text())
    managed_tests=json.loads((managed/'test-result.json').read_text())
    if (any(row['prepared_sha256']!=expected[name] for name,row in managed_manifest['files'].items())
            or managed_tests.get('managed_config_checks_passed') is not True):
        raise RuntimeError('Matching managed policy evidence required')
    if ('Cr_ValidateManagedPolicy' in (source/'Sandboxie/core/drv/conf.c').read_text(encoding='utf-8')
            and managed_tests.get('candidate_policy_gate_passed') is not True):
        raise RuntimeError('Candidate-policy gate evidence required')
    if 'Every fixed managed box' in (source/'Sandboxie/core/drv/conf.c').read_text(encoding='utf-8'):
        from prepare_managed_config import managed_policy_contract,managed_forbidden_settings
        boxes,settings=managed_policy_contract()
        contract_hash=hashlib.sha256(json.dumps((boxes,settings),separators=(',',':')).encode()).hexdigest()
        forbidden=managed_forbidden_settings()
        if (type(managed_tests.get('managed_box_policy_checks')) is not int
                or managed_tests['managed_box_policy_checks']!=len(boxes)*(4+6*len(settings))
                or managed_tests.get('managed_policy_contract_sha256')!=contract_hash
                or type(managed_tests.get('managed_forbidden_setting_checks')) is not int
                or managed_tests['managed_forbidden_setting_checks']!=(len(boxes)+1)*len(forbidden)*12
                or managed_tests.get('managed_forbidden_contract_sha256')!=hashlib.sha256(json.dumps(forbidden,separators=(',',':')).encode()).hexdigest()
                or managed_tests.get('managed_policy_test_sha256')!=sha(ROOT/'src/tests/native/ManagedPolicyTests.c')):
            raise RuntimeError('Matching managed box policy evidence required')
    if ('The managed policy is self-contained' in (source/'Sandboxie/core/drv/conf.c').read_text(encoding='utf-8')
            and any(managed_tests.get('managed_'+case+'_rejected_before_external_io') is not True
                    for case in ('include','missing'))):
        raise RuntimeError('Managed external-include refusal evidence required')
    if ('noncanonical 64-bit input' in (source/'Sandboxie/core/drv/conf.c').read_text(encoding='utf-8')
            and managed_tests.get('reload_invalid-flags_passed') is not True):
        raise RuntimeError('Reload argument validation evidence required')
    if ('unprotected post-reload state' in (source/'Sandboxie/core/drv/conf.c').read_text(encoding='utf-8')
            and any(managed_tests.get('reload_'+mode+'_passed') is not True
                    for mode in ('plain-wfp-lost','plain-object-lost'))):
        raise RuntimeError('Post-reload readiness loss evidence required')
    if 'BOOLEAN require_ready' in (source/'Sandboxie/core/drv/conf.c').read_text(encoding='utf-8'):
        modes=('wfp-lost','object-lost','waiting-wfp-lost','waiting-object-lost','startup','ready')
        if (any(managed_tests.get('publication_'+mode+'_passed') is not True for mode in modes)
                or managed_tests.get('publication_source_sha256')!=expected['Sandboxie/core/drv/conf.c']
                or managed_tests.get('publication_test_sha256')!=sha(ROOT/'src/tests/native/ManagedPublicationTests.c')):
            raise RuntimeError('Matching configuration publication evidence required')
    if ('Sandboxie/core/drv/driver.c' in managed_manifest['files']
            and managed_tests.get('unload_authorization_lifecycle_checks')!=384):
        raise RuntimeError('Driver unload authorization evidence required')
    if ('Sandboxie/core/drv/util.c' in managed_manifest['files']
            and managed_tests.get('exact_service_identity_checks')!=39):
        raise RuntimeError('Exact service identity evidence required')
    if 'Development certificates and OS test mode are not image authority' in (source/'Sandboxie/core/drv/util.c').read_text(encoding='utf-8'):
        fields={'caller_signature_checks':16,'caller_signature_mismatches':0,
                'caller_invalid_signature_accepted':0,'caller_signature_checks_skipped':0}
        if (any(type(managed_tests.get(k)) is not int or managed_tests[k]!=v for k,v in fields.items())
                or managed_tests.get('caller_signature_source_sha256')!=expected['Sandboxie/core/drv/util.c']
                or managed_tests.get('caller_signature_test_sha256')!=sha(ROOT/'src/tests/native/ManagedCallerSignatureTests.c')):
            raise RuntimeError('Matching caller signature enforcement evidence required')
    if ('Sandboxie/core/drv/api.c' in managed_manifest['files']
            and managed_tests.get('service_port_authorization_checks')!=48):
        raise RuntimeError('Service port authorization evidence required')
    if ('Sandboxie/core/drv/api.c' in expected and
            'Managed process exemptions cannot override' in (source/'Sandboxie/core/drv/api.c').read_text(encoding='utf-8')):
        counts=('managed_exemption_setter_checks','managed_exemption_query_checks')
        if (any(type(managed_tests.get(k)) is not int or managed_tests[k]!=48 for k in counts)
                or managed_tests.get('exemption_source_sha256')!=expected['Sandboxie/core/drv/api.c']
                or managed_tests.get('exemption_test_sha256')!=sha(ROOT/'src/tests/native/ManagedExemptionTests.cpp')):
            raise RuntimeError('Matching process exemption evidence required')
    reset_evidence=[]
    session_name='Sandboxie/core/drv/session.c'
    if (session_name in expected and
            'Managed policy has no runtime force-disable exceptions' in (source/session_name).read_text(encoding='utf-8')):
        counts={'session_force_setters_checks':96,'session_force_queries_checks':16,
                'session_force_children_checks':4,'session_force_mutation_checks':1,'force_children_option_checks':4}
        if (any(type(managed_tests.get(k)) is not int or managed_tests[k]!=v for k,v in counts.items())
                or managed_tests.get('session_force_source_sha256')!=expected[session_name]
                or managed_tests.get('session_force_test_sha256')!=sha(ROOT/'src/tests/native/ManagedSessionForceTests.cpp')
                or managed_tests.get('force_disable_source_sha256')!=expected.get('Sandboxie/apps/start/start.cpp')
                or managed_tests.get('force_disable_test_sha256')!=sha(ROOT/'src/tests/native/ManagedDisableForceTests.cpp')):
            raise RuntimeError('Matching session force refusal evidence required')
    api_name='Sandboxie/core/drv/api.c'
    if (api_name in expected and
            'Secure parameter writes belong to the exact SYSTEM service image' in (source/api_name).read_text(encoding='utf-8')):
        counts={'secure_param_role_checks':64,'secure_param_startup_checks':4}
        if (any(type(managed_tests.get(k)) is not int or managed_tests[k]!=v for k,v in counts.items())
                or managed_tests.get('secure_param_source_sha256')!=expected[api_name]
                or managed_tests.get('secure_param_test_sha256')!=sha(ROOT/'src/tests/native/ManagedSecureParamTests.cpp')):
            raise RuntimeError('Matching secure-parameter role evidence required')
    start_name='Sandboxie/apps/start/start.cpp'
    if (start_name in expected and
            'Force-disable refusal must stop before Program_Start' in (source/start_name).read_text(encoding='utf-8')):
        counts=('force_disable_command_checks','force_disable_launch_checks')
        if (any(type(managed_tests.get(k)) is not int or managed_tests[k]!=10 for k in counts)
                or managed_tests.get('force_disable_source_sha256')!=expected[start_name]
                or managed_tests.get('force_disable_test_sha256')!=sha(ROOT/'src/tests/native/ManagedDisableForceTests.cpp')):
            raise RuntimeError('Matching force-disable status evidence required')
    if 'Sandboxie/core/drv/api.h' in managed_manifest['files']:
        reset_path=managed/'service-reset-tests/result.json'
        reset=json.loads(reset_path.read_text())
        from verify_service_reset import CASES
        wanted={(label,case):0 if label=='prepared' or case=='own-empty-port' else 1
                for label in ('prepared','original') for case in CASES}
        actual={(row['source'],row['case']):row['exit_code'] for row in reset['cases']}
        if (reset.get('passed') is not True or reset.get('installed') is not False
                or reset.get('kernel_test') is not False or len(reset['cases'])!=len(wanted)
                or actual!=wanted or reset.get('prepared_source_sha256')!=expected['Sandboxie/core/drv/api.c']
                or reset.get('test_source_sha256')!=sha(ROOT/'src/tests/native/ManagedServiceResetTests.cpp')):
            raise RuntimeError('Matching service registration cleanup evidence required')
        reset_evidence=[reset_path]
    if 'Sandboxie/core/drv/wfp.c' in changes:
        folder=combined/'wfp-lifecycle'
        manifest=json.loads((folder/'manifest.json').read_text())
        tests=json.loads((folder/'test-result.json').read_text())
        modes=('allocation','subscription','callbacks','bfe-stopped',
               'enabled-without-callbacks','enabled-bfe-stopped','engine-before-commit')
        if (manifest['prepared_sha256']!=expected['Sandboxie/core/drv/wfp.c']
                or tests.get('upstream_negative_controls')!=7 or any(tests.get(mode) is not True for mode in modes)
                or tests.get('callback_cases')!=13 or tests.get('callback_upstream_negative_controls')!=10
                or tests.get('registration_cases')!=5 or tests.get('registration_upstream_negative_controls')!=4):
            raise RuntimeError('Matching WFP lifecycle evidence required')
        lifecycle_evidence=[folder/'manifest.json',folder/'test-result.json']
    receipts = {}
    for kind in ('driver', 'core-x86', 'core-x64'):
        path = combined / 'ewdk-build' / (kind + '-receipt.json')
        row = json.loads(path.read_text())
        if row['returncode'] != 0 or row['source_manifest_sha256'] != sha(combined / 'source-manifest.json'):
            raise RuntimeError('Successful matching build receipt required')
        receipts[kind] = row
    from managed_compiler import build as build_managed
    managed_build=build_managed(output/'managed-build',['ClaudeResetGateway','GatewayFunctionalTests'],kit_root=kit_root)
    runtime=output/'runtime';runtime.mkdir()
    gateway=runtime/'ClaudeResetGateway.exe'
    shutil.copyfile(output/'managed-build/ClaudeResetGateway.exe',gateway)
    if sha(gateway)!=managed_build['builds']['ClaudeResetGateway']['sha256']:
        raise RuntimeError('Managed gateway copy differs')
    harness=ROOT/'src/tests/native/GatewayFunctionalTests.cs'
    shutil.copyfile(output/'managed-build/GatewayFunctionalTests-result.json',output/'gateway-functional-tests.json')
    files = [gateway]
    for platform, arch in [('x64', 0x8664), ('Win32', 0x14c)]:
        base = source / 'Sandboxie/Bin' / platform / 'SbieRelease'
        destinations = runtime / platform
        destinations.mkdir()
        for item in sorted(base.iterdir()):
            if item.suffix.lower() not in ('.exe', '.dll', '.sys'): continue
            if machine(item) != arch: raise RuntimeError('Unexpected PE architecture: ' + item.name)
            target = destinations / item.name
            shutil.copyfile(item, target)
            if sha(target) != sha(item): raise RuntimeError('Copy verification failed')
            files.append(target)
    for required in ('x64/SbieDrv.sys', 'x64/SbieSvc.exe', 'x64/SbieDll.dll', 'Win32/SbieDll.dll', 'x64/Start.exe'):
        if not (runtime / required).is_file(): raise RuntimeError('Missing runtime: ' + required)
    if machine(gateway) != 0x8664: raise RuntimeError('Gateway architecture mismatch')
    values = ','.join("'" + str(p).replace("'", "''") + "'" for p in files)
    signatures = ps_json('@(' + values + ')|ForEach-Object {$s=Get-AuthenticodeSignature -LiteralPath $_; '
        '@{path=$_;status=$s.Status.ToString()}}|ConvertTo-Json -Compress')
    evidence = output / 'evidence'
    evidence.mkdir()
    shutil.copyfile(output/'managed-build/managed-build-receipt.json',evidence/'managed-build-receipt.json')
    for name in ('source-manifest.json', 'combined.patch', 'combined-receipt.json'):
        shutil.copyfile(combined / name, evidence / name)
    shutil.copytree(combined / 'ewdk-build', evidence / 'ewdk-build', ignore=shutil.ignore_patterns('*.cmd', 'empty-user-props'))
    shutil.copyfile(ROOT / 'src/native/ClaudeResetGateway.cs', evidence / 'ClaudeResetGateway.cs')
    shutil.copyfile(ROOT / 'third_party/sources/sandboxie-lock.json', evidence / 'sandboxie-lock.json')
    for path in queue_evidence:shutil.copyfile(path,evidence/'queue-event-ownership-result.json')
    for path in reply_evidence:shutil.copyfile(path,evidence/'queue-reply-ownership-result.json')
    for path in queue_lifecycle:shutil.copyfile(path,evidence/'queue-request-lifecycle-result.json')
    for path in service_evidence:shutil.copyfile(path,evidence/('service-'+path.name))
    for path in classification_evidence:shutil.copyfile(path,evidence/'broker-classification-result.json')
    for path in lifecycle_evidence:shutil.copyfile(path,evidence/('wfp-lifecycle-'+path.name))
    for name in ('manifest.json','test-result.json'):shutil.copyfile(managed/name,evidence/('managed-config-'+name))
    for path in reset_evidence:shutil.copyfile(path,evidence/'service-reset-test-result.json')
    for path in trust_evidence:shutil.copyfile(path,evidence/('runtime-trust-'+path.name))
    result = {'schema': 1, 'utc': datetime.now(timezone.utc).isoformat(),
        'status': 'unsigned_build_candidate_not_installable', 'builds': receipts,
        'gateway_source_sha256': managed_build['source_sha256']['src/native/ClaudeResetGateway.cs'],
        'gateway_test_source_sha256': managed_build['source_sha256']['src/tests/native/GatewayFunctionalTests.cs'], 'gateway_functional_tests_passed': True,
        'compiler_sha256': managed_build['compiler_sha256'], 'compiler_signature': managed_build['compiler_signature'],
        'managed_build':managed_build,
        'runtime': {p.relative_to(output).as_posix(): {'sha256': sha(p), 'bytes': p.stat().st_size,
            'machine': hex(machine(p)), 'signature': next(s['status'] for s in signatures if s['path'] == str(p))} for p in files},
        'installed': False, 'loaded': False, 'production_clients_permitted': False,
        'runtime_public_key_sha256': runtime_key,
        'runtime_key_authority_verified': False,
        'detached_runtime_signing': ('outstanding: prepared public key has no approved authority or supplied runtime signatures'
            if runtime_key else 'outstanding: upstream embedded ECDSA public key does not trust locally rebuilt components'),
        'limits': ['Trusted driver signing outstanding', 'Kernel runtime acceptance outstanding',
            'Independent Sandboxie detached runtime signatures and trust-root review outstanding',
            'Source reproducibility across clean builds not yet established',
            'Review bundle only; not a driver submission CAB or final redistributable']}
    templates = runtime / 'x64/Templates.ini'
    shutil.copyfile(source / 'Sandboxie/install/Templates.ini', templates)
    result['runtime'][templates.relative_to(output).as_posix()] = {
        'sha256':sha(templates),'bytes':templates.stat().st_size,
        'machine':None,'signature':'NotApplicable: pinned configuration data'}
    (output / 'candidate-manifest.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({'status': result['status'], 'runtime_files': len(result['runtime']), 'path': str(output)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--combined', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--kit-root', type=Path, help='Explicit extracted EWDK; all pinned compiler checks remain required')
    args = parser.parse_args()
    main(args.combined, args.output, kit_root=args.kit_root)
