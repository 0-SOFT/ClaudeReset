"""Compile extracted policy path functions; upstream must fail the same test."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import ctypes
from prepare_managed_config import function,managed_policy_contract,managed_forbidden_settings

ROOT = Path(__file__).resolve().parents[1]


def verify(prepared, compiler):
    manifest = json.loads((prepared / 'manifest.json').read_text())
    if hashlib.sha256((prepared/'ManagedMessageIds.h').read_bytes()).hexdigest()!=manifest['message_ids_sha256']:
        raise RuntimeError('Managed message identifiers changed')
    if hashlib.sha256((prepared/'ManagedApiFlags.h').read_bytes()).hexdigest()!=manifest['api_flags_sha256']:
        raise RuntimeError('Managed API flags changed')
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(ROOT / 'work/toolchains/zig-cache'))
    results = {}
    for version in ('prepared', 'original'):
        folder = prepared / ('test-' + version)
        folder.mkdir(exist_ok=True)
        boxes,settings=managed_policy_contract()
        forbidden=managed_forbidden_settings()
        def wide_array(values):return ','.join('L'+json.dumps(value) for value in values)
        (folder/'ManagedPolicyFixture.h').write_text(
            'enum {BOX_COUNT='+str(len(boxes))+',SETTING_COUNT='+str(len(settings))+',FORBIDDEN_COUNT='+str(len(forbidden))+'};\n'
            'static const wchar_t *FixtureForbidden[]={'+wide_array(forbidden)+'};\n'
            'static const wchar_t *FixtureBoxes[]={'+wide_array(boxes)+'};\n'
            'static const wchar_t *FixtureKeys[]={'+wide_array(k for k,v in settings)+'};\n'
            'static const wchar_t *FixtureValues[]={'+wide_array(v for k,v in settings)+'};\n',encoding='utf-8')
        for name, item in manifest['files'].items():
            path = prepared / version / name
            data = path.read_bytes()
            digest_key = 'prepared_sha256' if version == 'prepared' else 'original_normalized_sha256'
            if hashlib.sha256(data).hexdigest() != item[digest_key]:
                raise RuntimeError('Test source changed')
            source = data.decode('utf-8')
            if name.endswith('/conf.c'):
                signature='_FX NTSTATUS Conf_Read(ULONG session_id, BOOLEAN require_ready)' if version=='prepared' else '_FX NTSTATUS Conf_Read(ULONG session_id)'
                read=function(source,signature)
                if version=='prepared':
                    if (source.count('Conf_Read((ULONG)parms[1], TRUE)')!=1
                            or source.count('Conf_Read(-1, FALSE)')!=1
                            or source.count('Conf_Read(')!=4):
                        raise RuntimeError('Unreviewed configuration publication caller')
                publication=read[read.index('        BOOLEAN done = FALSE;'):read.index('    Mem_Free(path, path_len);',read.index('        BOOLEAN done = FALSE;'))]
                (folder/'ManagedPublicationUnderTest.inc').write_text(
                    'static NTSTATUS Publish(CONF_DATA data, BOOLEAN require_ready) {\n'
                    'NTSTATUS status=STATUS_SUCCESS; POOL *pool=data.pool;\nif(NT_SUCCESS(status)){\n'+publication+
                    'if(pool)Pool_Delete(pool);return status;\n}\n',encoding='utf-8')
                includes=function(source,'_FX NTSTATUS Conf_Import_AllIncludes(CONF_DATA *data, ULONG session_id)')
                include_call='status = Conf_Import_AllIncludes(&data, session_id);' if version=='prepared' else 'Conf_Import_AllIncludes(&data, session_id);'
                if read.count(include_call)!=1:raise RuntimeError('Unreviewed include dispatch status handling')
                (folder/'ManagedIncludesUnderTest.inc').write_text(includes+
                    '\nstatic NTSTATUS ReadIncludes(CONF_DATA *input){ CONF_DATA data=*input; ULONG session_id=0; NTSTATUS status=0;\n'+
                    include_call+'\nreturn status;\n}\n',encoding='utf-8')
                gate=read[read.index('    Conf_AdjustUseCount(FALSE);')+len('    Conf_AdjustUseCount(FALSE);'):read.index('        BOOLEAN done = FALSE;')]
                validator=function(source,'_FX NTSTATUS Cr_ValidateManagedPolicy(CONF_DATA *data)') if version=='prepared' else ''
                (folder/'ManagedPolicyUnderTest.inc').write_text(validator+
                    '\nstatic bool CandidateMayReplace(CONF_DATA data,NTSTATUS status){\n'+gate+
                    'return true;\n}\nreturn false;\n}\n',encoding='utf-8')
                reload=function(source,'_FX NTSTATUS Conf_Api_Reload(PROCESS *proc, ULONG64 *parms)')
                (folder/'ManagedReloadUnderTest.inc').write_text(reload,encoding='utf-8')
                end=reload.index('    /* Serialize') if version=='prepared' else reload.index('    flags = (ULONG)parms[2];')
                reload=reload[:end]+'    return STATUS_SUCCESS;\n}'
                update=function(source,'_FX NTSTATUS Conf_Api_Update(PROCESS *proc, ULONG64 *parms)')
                if version=='original':
                    update=update[:update.index('    //\n    // prepare parameters')]+ '    return STATUS_SUCCESS;\n}'
                (folder/'ManagedApiUnderTest.inc').write_text(reload+'\n'+update,encoding='utf-8')
                start = source.index('    /* ClaudeReset: require') if version == 'prepared' else source.index('    UNICODE_STRING IniPath = ')
                fragment = source[start:source.index('    data.pool = pool;', start)]
                target = 'ManagedDriverUnderTest.inc'
                (folder/'ManagedMergeUnderTest.inc').write_text(
                    function(source,'_FX NTSTATUS Conf_Merge_AllTemplates(CONF_DATA *data, ULONG session_id)'),encoding='utf-8')
                if version == 'prepared':
                    begin = source.index('        /* Template lookup must')
                    end = source.index('\n\n        status = Stream_Open(', begin)
                    (folder/'ManagedTemplatesUnderTest.inc').write_text(source[begin:end], encoding='utf-8')
            elif name.endswith('/session.c'):
                (folder/'ManagedSessionForceUnderTest.inc').write_text(
                    function(source,'_FX NTSTATUS Session_Api_DisableForce(PROCESS *proc, ULONG64 *parms)')+'\n'+
                    function(source,'_FX NTSTATUS Session_Api_ForceChildren(PROCESS *proc, ULONG64 *parms)'),encoding='utf-8')
                continue
            elif name.endswith('/api.h'):
                continue
            elif name.endswith('/api.c'):
                (folder/'ManagedSecureParamUnderTest.inc').write_text(
                    function(source,'_FX NTSTATUS Api_SetSecureParam(PROCESS* proc, ULONG64* parms)'),encoding='utf-8')
                (folder/'ManagedExemptionUnderTest.inc').write_text(
                    function(source,'_FX NTSTATUS Api_ProcessExemptionControl(PROCESS *proc, ULONG64 *parms)'),encoding='utf-8')
                (folder/'ManagedServicePortUnderTest.inc').write_text(
                    function(source,'_FX NTSTATUS Api_SetServicePort(PROCESS *proc, ULONG64 *parms)'),encoding='utf-8')
                continue
            elif name.endswith('/util.c'):
                (folder/'ManagedCallerSignatureUnderTest.inc').write_text(
                    function(source,'_FX BOOLEAN MyIsCallerSigned(void)'),encoding='utf-8')
                (folder/'ManagedServiceIdentityUnderTest.inc').write_text(
                    function(source,'_FX BOOLEAN MyIsCallerMyServiceProcess(void)'),encoding='utf-8')
                continue
            elif name.endswith('/driver.c'):
                (folder/'ManagedUnloadUnderTest.inc').write_text(
                    function(source,'_FX NTSTATUS Driver_Api_Unload(PROCESS *proc, ULONG64 *parms)'),encoding='utf-8')
                continue
            elif name.endswith('/start.cpp'):
                option=function(source,'else if (_wcsnicmp(cmd, L"force_children", 14) == 0 ||')
                (folder/'ManagedForceChildrenOptionUnderTest.inc').write_text(option.removeprefix('else '),encoding='utf-8')
                begin=source.index('        ULONG NewState = TRUE;',source.index('wcsncmp(cmd, disable_force, 13)'))
                end=source.index('\n    }',begin)
                (folder/'ManagedDisableCommandUnderTest.inc').write_text(source[begin:end],encoding='utf-8')
                (folder/'ManagedDisableLaunchUnderTest.inc').write_text(
                    function(source[source.index('            if (disable_force_on_this_program) {\n\n                ULONG NewState'):],
                             '            if (disable_force_on_this_program) {'),encoding='utf-8')
                start=source.index('        } else if (_wcsnicmp(cmd, L"reload", 6) == 0) {')
                start=source.index('{',start)+1
                end=source.index('        //',start)
                (folder/'ManagedStartReloadUnderTest.inc').write_text(source[start:end],encoding='utf-8')
                continue
            elif name.endswith('/update.c'):
                (folder/'ManagedIniUpdateUnderTest.inc').write_text(function(source,'int DoUpdate(void)'),encoding='utf-8')
                continue
            else:
                fragment = function(source, 'bool SbieIniServer::GetIniPath(WCHAR **IniPath, BOOLEAN *IsHomePath)')
                target = 'ManagedServiceUnderTest.inc'
                handler=function(source,'MSG_HEADER *SbieIniServer::Handler2(MSG_HEADER *msg)')
                prefix=handler[handler.index('{')+1:handler.index('    HANDLE idProcess =')]
                (folder/'ManagedMutationUnderTest.inc').write_text(prefix,encoding='utf-8')
            (folder / target).write_text(fragment, encoding='utf-8')
        force_exe=folder/'ManagedSessionForceTests.exe'
        built=subprocess.run([str(compiler),'c++','-std=c++17','-I'+str(folder),
            str(ROOT/'src/tests/native/ManagedSessionForceTests.cpp'),'-o',str(force_exe)],
            capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace')[-5000:])
        for mode in ('setters','queries','children','mutation'):
            checked=subprocess.run([str(force_exe),mode],capture_output=True,timeout=15,creationflags=0x08000000)
            if version=='prepared' or mode=='queries':
                if checked.returncode:raise RuntimeError(checked.stderr.decode())
                if version=='prepared':results.update(json.loads(checked.stdout))
            elif checked.returncode!=1 or b'check failed' not in checked.stderr:
                raise RuntimeError('Upstream session force '+mode+' control did not fail')
        secure_exe=folder/'ManagedSecureParamTests.exe'
        built=subprocess.run([str(compiler),'c++','-std=c++17','-I'+str(folder),
            str(ROOT/'src/tests/native/ManagedSecureParamTests.cpp'),'-o',str(secure_exe)],
            capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace')[-5000:])
        checked=subprocess.run([str(secure_exe)],capture_output=True,timeout=15,creationflags=0x08000000)
        if version=='prepared':
            if checked.returncode:raise RuntimeError(checked.stderr.decode())
            results.update(json.loads(checked.stdout))
        elif checked.returncode!=1 or b'check failed' not in checked.stderr:
            raise RuntimeError('Upstream secure-parameter role control did not fail')
        exemption_exe=folder/'ManagedExemptionTests.exe'
        built=subprocess.run([str(compiler),'c++','-std=c++17','-I'+str(folder),
            str(ROOT/'src/tests/native/ManagedExemptionTests.cpp'),'-o',str(exemption_exe)],
            capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace')[-5000:])
        for arguments in ([],['--queries']):
            checked=subprocess.run([str(exemption_exe),*arguments],capture_output=True,timeout=15,creationflags=0x08000000)
            if version=='prepared' or arguments:
                if checked.returncode:raise RuntimeError(checked.stderr.decode())
                if version=='prepared':results.update(json.loads(checked.stdout))
            elif checked.returncode!=1 or b'check failed' not in checked.stderr:
                raise RuntimeError('Upstream process exemption setter control did not fail')
        disable_exe=folder/'ManagedDisableForceTests.exe'
        built=subprocess.run([str(compiler),'c++','-std=c++17','-I'+str(folder),
            str(ROOT/'src/tests/native/ManagedDisableForceTests.cpp'),'-o',str(disable_exe)],
            capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace')[-5000:])
        for mode in ('command','launch','force-option'):
            checked=subprocess.run([str(disable_exe),mode],capture_output=True,timeout=15,creationflags=0x08000000)
            if version=='prepared':
                if checked.returncode:raise RuntimeError(checked.stderr.decode())
                results.update(json.loads(checked.stdout))
            elif checked.returncode!=1 or b'check failed' not in checked.stderr:
                raise RuntimeError('Upstream force-disable '+mode+' status control did not fail')
        include_exe=folder/'ManagedIncludeTests.exe'
        built=subprocess.run([str(compiler),'cc','-std=c11','-I'+str(folder),
            str(ROOT/'src/tests/native/ManagedIncludeTests.c'),'-o',str(include_exe)],
            capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace')[-5000:])
        for case in ('include','missing'):
            tested=subprocess.run([str(include_exe),case],capture_output=True,timeout=15,creationflags=0x08000000)
            if version=='prepared':
                if tested.returncode:raise RuntimeError(tested.stderr.decode())
                results.update(json.loads(tested.stdout))
            elif tested.returncode!=1 or b'check failed' not in tested.stderr:
                raise RuntimeError('Upstream include negative control did not fail: '+case)
        for name in ('ManagedServiceIdentityTests','ManagedServicePortTests'):
            exe=folder/(name+'.exe')
            built=subprocess.run([str(compiler),'c++','-std=c++17','-I'+str(folder),
                str(ROOT/'src/tests/native'/(name+'.cpp')),'-o',str(exe)],
                capture_output=True,timeout=180,env=env,creationflags=0x08000000)
            if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace')[-5000:])
            tested=subprocess.run([str(exe)],capture_output=True,timeout=15,creationflags=0x08000000)
            if version=='prepared':
                if tested.returncode:raise RuntimeError(tested.stderr.decode())
                results.update(json.loads(tested.stdout))
            elif tested.returncode!=1 or b'check failed' not in tested.stderr:
                raise RuntimeError('Upstream '+name+' control did not fail')
            if name=='ManagedServicePortTests':
                tested=subprocess.run([str(exe),'--handle-only'],capture_output=True,timeout=15,creationflags=0x08000000)
                if version=='prepared' and tested.returncode:raise RuntimeError('User port handle mode differs')
                if version=='original' and (tested.returncode!=1 or b'check failed' not in tested.stderr):
                    raise RuntimeError('Upstream kernel-mode user-handle control did not fail')
        unload_exe=folder/'ManagedUnloadTests.exe'
        built=subprocess.run([str(compiler),'c++','-std=c++17','-I'+str(folder),
            str(ROOT/'src/tests/native/ManagedUnloadTests.cpp'),'-o',str(unload_exe)],
            capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace')[-5000:])
        unloaded=subprocess.run([str(unload_exe)],capture_output=True,timeout=15,creationflags=0x08000000)
        if version=='prepared':
            if unloaded.returncode:raise RuntimeError(unloaded.stderr.decode())
            results.update(json.loads(unloaded.stdout))
        elif unloaded.returncode!=1 or b'check failed' not in unloaded.stderr:
            raise RuntimeError('Upstream unload authorization control did not fail')
        policy_exe=folder/'ManagedPolicyTests.exe'
        built=subprocess.run([str(compiler),'cc','-std=c11','-I'+str(folder),
            str(ROOT/'src/tests/native/ManagedPolicyTests.c'),'-o',str(policy_exe)],
            capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace')[-5000:])
        policy=subprocess.run([str(policy_exe)],capture_output=True,timeout=15,creationflags=0x08000000)
        if version=='prepared':
            if policy.returncode:raise RuntimeError(policy.stderr.decode())
            results.update(json.loads(policy.stdout))
        elif policy.returncode!=1 or b'check failed' not in policy.stderr:
            raise RuntimeError('Upstream candidate-policy gate control did not fail')
        boxes_only=subprocess.run([str(policy_exe),'--boxes-only'],capture_output=True,timeout=15,creationflags=0x08000000)
        if version=='prepared':
            if boxes_only.returncode:raise RuntimeError(boxes_only.stderr.decode())
            if json.loads(boxes_only.stdout).get('managed_box_policy_checks')!=len(boxes)*(4+6*len(settings)):
                raise RuntimeError('Managed box policy coverage differs')
            if json.loads(boxes_only.stdout).get('managed_forbidden_setting_checks')!=(len(boxes)+1)*len(forbidden)*12:
                raise RuntimeError('Managed exception policy coverage differs')
        elif boxes_only.returncode!=1 or b'check failed' not in boxes_only.stderr:
            raise RuntimeError('Upstream per-box candidate control did not fail')
        ini_exe=folder/'ManagedIniUpdateTests.exe'
        built=subprocess.run([str(compiler),'cc','-std=c11','-I'+str(folder),
            str(ROOT/'src/tests/native/ManagedIniUpdateTests.c'),'-o',str(ini_exe)],
            capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace')[-5000:])
        ini_result=subprocess.run([str(ini_exe)],capture_output=True,timeout=15,creationflags=0x08000000)
        if version=='prepared':
            if ini_result.returncode:raise RuntimeError(ini_result.stderr.decode())
            results.update(json.loads(ini_result.stdout.splitlines()[-1]))
        elif ini_result.returncode!=1 or b'check failed' not in ini_result.stderr:
            raise RuntimeError('Upstream CLI mutation error control did not fail')
        reload_result=subprocess.run([str(ini_exe),'--reload-only'],capture_output=True,timeout=15,creationflags=0x08000000)
        if version=='prepared' and reload_result.returncode:
            raise RuntimeError('CLI reload status was lost')
        if version=='original' and (reload_result.returncode!=1 or b'check failed' not in reload_result.stderr):
            raise RuntimeError('Upstream CLI reload error control did not fail')
        exe = folder / 'ManagedConfigTests.exe'
        definitions = ['-DTEST_MANAGED_TEMPLATES'] if version == 'prepared' else []
        built = subprocess.run([str(compiler), 'c++', '-std=c++17', '-Wno-c++11-narrowing', *definitions, '-I'+str(folder),
                                str(ROOT/'src/tests/native/ManagedConfigTests.cpp'), '-o', str(exe)],
                               capture_output=True, timeout=180, env=env, creationflags=0x08000000)
        if built.returncode:
            raise RuntimeError(built.stderr.decode(errors='replace')[-5000:])
        result = subprocess.run([str(exe)], capture_output=True, timeout=15, creationflags=0x08000000)
        if version == 'prepared':
            if result.returncode: raise RuntimeError(result.stderr.decode())
            results.update(json.loads(result.stdout))
        elif result.returncode != 1 or b'check failed' not in result.stderr:
            raise RuntimeError('Upstream negative control did not fail')
        merge_exe=folder/'ManagedTemplateMergeTests.exe'
        built=subprocess.run([str(compiler),'c++','-std=c++17','-I'+str(folder),
            str(ROOT/'src/tests/native/ManagedTemplateMergeTests.cpp'),'-o',str(merge_exe)],
            capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace')[-5000:])
        merged=subprocess.run([str(merge_exe)],capture_output=True,timeout=15,creationflags=0x08000000)
        if version=='prepared':
            if merged.returncode:raise RuntimeError(merged.stderr.decode())
            results.update(json.loads(merged.stdout))
        elif merged.returncode!=1 or b'check failed' not in merged.stderr:
            raise RuntimeError('Upstream implicit-template control did not fail')
        failure=subprocess.run([str(merge_exe),'--global-error'],capture_output=True,timeout=15,creationflags=0x08000000)
        if version=='prepared' and failure.returncode:
            raise RuntimeError('Global template failure was lost')
        if version=='original' and (failure.returncode!=1 or b'check failed' not in failure.stderr):
            raise RuntimeError('Upstream global-error negative control did not fail')
        mutation_exe=folder/'ManagedMutationTests.exe'
        built=subprocess.run([str(compiler),'c++','-std=c++17','-I'+str(folder),'-I'+str(prepared),
            str(ROOT/'src/tests/native/ManagedMutationTests.cpp'),'-o',str(mutation_exe)],
            capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace')[-5000:])
        mutation=subprocess.run([str(mutation_exe)],capture_output=True,timeout=15,creationflags=0x08000000)
        if version=='prepared':
            if mutation.returncode:raise RuntimeError(mutation.stderr.decode())
            results.update(json.loads(mutation.stdout))
        elif mutation.returncode!=1 or b'check failed' not in mutation.stderr:
            raise RuntimeError('Upstream mutable-policy negative control did not fail')
        api_exe=folder/'ManagedApiTests.exe'
        built=subprocess.run([str(compiler),'c++','-std=c++17','-I'+str(folder),
            str(ROOT/'src/tests/native/ManagedApiTests.cpp'),'-o',str(api_exe)],
            capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace')[-5000:])
        for mode in ('reload','update'):
            tested=subprocess.run([str(api_exe),mode],capture_output=True,timeout=15,creationflags=0x08000000)
            if version=='prepared':
                if tested.returncode:raise RuntimeError(tested.stderr.decode())
                results.update(json.loads(tested.stdout))
            elif tested.returncode!=1 or b'check failed' not in tested.stderr:
                raise RuntimeError('Upstream '+mode+' authorization negative control did not fail')
        reload_exe=folder/'ManagedReloadTests.exe'
        definitions=['-DTEST_MANAGED_PUBLICATION'] if version=='prepared' else []
        built=subprocess.run([str(compiler),'cc','-x','c','-std=c11',*definitions,'-I'+str(folder),'-I'+str(prepared),
            str(ROOT/'src/tests/native/ManagedReloadTests.c'),'-o',str(reload_exe)],
            capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace')[-5000:])
        for mode in ('read-error','concurrency','wfp-failure','object-failure','enabled-not-ready',
                     'plain-wfp-not-ready','plain-object-not-ready','plain-wfp-lost','plain-object-lost',
                     'invalid-flags','certificate'):
            tested=subprocess.run([str(reload_exe),mode],capture_output=True,timeout=15,creationflags=0x08000000)
            if version=='prepared' or mode=='certificate':
                if tested.returncode:raise RuntimeError(tested.stderr.decode())
                if version=='prepared':results.update(json.loads(tested.stdout))
            elif tested.returncode!=1 or b'check failed' not in tested.stderr:
                raise RuntimeError('Upstream reload '+mode+' control did not fail')
        signer_exe=folder/'ManagedCallerSignatureTests.exe'
        built=subprocess.run([str(compiler),'cc','-std=c11','-I'+str(folder),
            str(ROOT/'src/tests/native/ManagedCallerSignatureTests.c'),'-o',str(signer_exe)],
            capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace')[-5000:])
        tested=subprocess.run([str(signer_exe)],capture_output=True,timeout=15,creationflags=0x08000000)
        signer=json.loads(tested.stdout)
        if version=='prepared':
            if tested.returncode or signer!=dict(caller_signature_checks=16,caller_signature_mismatches=0,
                    caller_invalid_signature_accepted=0,caller_signature_checks_skipped=0):
                raise RuntimeError('Caller image signature was bypassed')
            results.update(signer)
        elif tested.returncode!=1 or signer!=dict(caller_signature_checks=16,caller_signature_mismatches=10,
                caller_invalid_signature_accepted=5,caller_signature_checks_skipped=10):
            raise RuntimeError('Upstream signer bypass negative control differs')
        publication_exe=folder/'ManagedPublicationTests.exe'
        built=subprocess.run([str(compiler),'cc','-x','c','-std=c11','-I'+str(folder),
            str(ROOT/'src/tests/native/ManagedPublicationTests.c'),'-o',str(publication_exe)],
            capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace')[-5000:])
        for mode in ('wfp-lost','object-lost','waiting-wfp-lost','waiting-object-lost','startup','ready'):
            tested=subprocess.run([str(publication_exe),mode],capture_output=True,timeout=15,creationflags=0x08000000)
            if version=='prepared' or mode in ('startup','ready'):
                if tested.returncode:raise RuntimeError(tested.stderr.decode())
                if version=='prepared':results.update(json.loads(tested.stdout))
            elif tested.returncode!=1 or b'check failed' not in tested.stderr:
                raise RuntimeError('Upstream publication '+mode+' control did not fail')
    results['upstream_negative_control_failed_as_expected'] = True
    # Exercise the actual Windows namespace spelling against an owned temporary file.
    with tempfile.TemporaryDirectory(prefix='claudereset-global-path-') as folder:
        path = Path(folder) / 'policy.ini'
        path.write_bytes(b'owned namespace fixture')
        api = ctypes.WinDLL('kernel32', use_last_error=True)
        api.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                   ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        api.CreateFileW.restype = ctypes.c_void_p
        api.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = api.CreateFileW('\\\\?\\GLOBALROOT\\DosDevices\\Global\\'+str(path),
                                 0x80000000, 1, None, 3, 0, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        api.CloseHandle(handle)
    results['windows_global_namespace_open_passed'] = True
    results['publication_source_sha256']=manifest['files']['Sandboxie/core/drv/conf.c']['prepared_sha256']
    results['exemption_source_sha256']=manifest['files']['Sandboxie/core/drv/api.c']['prepared_sha256']
    results['exemption_test_sha256']=hashlib.sha256((ROOT/'src/tests/native/ManagedExemptionTests.cpp').read_bytes()).hexdigest()
    results['secure_param_source_sha256']=manifest['files']['Sandboxie/core/drv/api.c']['prepared_sha256']
    results['secure_param_test_sha256']=hashlib.sha256((ROOT/'src/tests/native/ManagedSecureParamTests.cpp').read_bytes()).hexdigest()
    results['session_force_source_sha256']=manifest['files']['Sandboxie/core/drv/session.c']['prepared_sha256']
    results['session_force_test_sha256']=hashlib.sha256((ROOT/'src/tests/native/ManagedSessionForceTests.cpp').read_bytes()).hexdigest()
    results['force_disable_source_sha256']=manifest['files']['Sandboxie/apps/start/start.cpp']['prepared_sha256']
    results['force_disable_test_sha256']=hashlib.sha256((ROOT/'src/tests/native/ManagedDisableForceTests.cpp').read_bytes()).hexdigest()
    results['publication_test_sha256']=hashlib.sha256((ROOT/'src/tests/native/ManagedPublicationTests.c').read_bytes()).hexdigest()
    results['caller_signature_source_sha256']=manifest['files']['Sandboxie/core/drv/util.c']['prepared_sha256']
    results['caller_signature_test_sha256']=hashlib.sha256((ROOT/'src/tests/native/ManagedCallerSignatureTests.c').read_bytes()).hexdigest()
    results['managed_policy_contract_sha256']=hashlib.sha256(json.dumps(managed_policy_contract(),separators=(',',':')).encode()).hexdigest()
    results['managed_policy_test_sha256']=hashlib.sha256((ROOT/'src/tests/native/ManagedPolicyTests.c').read_bytes()).hexdigest()
    results['managed_forbidden_contract_sha256']=hashlib.sha256(json.dumps(managed_forbidden_settings(),separators=(',',':')).encode()).hexdigest()
    results['limits'] = 'Extracted functions with stubs; not live driver acceptance'
    (prepared/'test-result.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps(results))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prepared-root', type=Path, required=True)
    p.add_argument('--compiler', type=Path, default=ROOT/'work/toolchains/zig-pypi-0.13.0/ziglang/zig.exe')
    a = p.parse_args()
    verify(a.prepared_root.resolve(), a.compiler.resolve())
