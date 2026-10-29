"""Compile exact WFP_Load; each upstream negative control must reproduce."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from prepare_managed_config import function

ROOT=Path(__file__).resolve().parents[1]
MODES=('allocation','subscription','callbacks','bfe-stopped','enabled-without-callbacks','enabled-bfe-stopped','engine-before-commit')


def verify(prepared,compiler):
    manifest=json.loads((prepared/'manifest.json').read_text());results={}
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(ROOT/'work/toolchains/zig-cache'))
    for version in ('prepared','original'):
        data=(prepared/version/manifest['file']).read_bytes()
        if hashlib.sha256(data).hexdigest()!=manifest[version+'_sha256']:raise RuntimeError('Changed WFP source')
        folder=prepared/('test-'+version);folder.mkdir()
        ready=function(data.decode(),'_FX BOOLEAN WFP_IsReady(void)') if version=='prepared' else ''
        (folder/'WfpLoadUnderTest.inc').write_text(ready+'\n'+function(data.decode(),'_FX BOOLEAN WFP_Load(void)'),encoding='utf-8')
        exe=folder/'WfpLoadTests.exe'
        built=subprocess.run([str(compiler),'cc','-std=c11','-I'+str(folder),
            str(ROOT/'src/tests/native/WfpLoadTests.c'),'-o',str(exe)],capture_output=True,timeout=180,
            creationflags=0x08000000,env=env)
        if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace'))
        for mode in MODES:
            result=subprocess.run([str(exe),mode],capture_output=True,timeout=15,creationflags=0x08000000)
            if version=='prepared':
                if result.returncode:raise RuntimeError(mode+': '+result.stderr.decode())
                results[mode]=True
            elif result.returncode!=1 or b'check failed' not in result.stderr:
                raise RuntimeError('Upstream '+mode+' did not reproduce')
        callbacks=(function(data.decode(),'_FX BOOLEAN WFP_RemoveCallouts(void)')+'\n' if version=='prepared' else '')
        callbacks+='\n'.join(function(data.decode(),signature) for signature in (
            '_FX BOOLEAN WFP_Install_Callbacks(void)','_FX void WFP_Uninstall_Callbacks(void)',
            '_FX void WFP_state_changed(_Inout_ void* context, _In_ FWPM_SERVICE_STATE newState)'))
        (folder/'WfpCallbacksUnderTest.inc').write_text(callbacks,encoding='utf-8')
        callback_exe=folder/'WfpCallbackTests.exe'
        definitions=['-DTEST_OWNERSHIP'] if version=='prepared' else []
        built=subprocess.run([str(compiler),'cc','-std=c11',*definitions,'-I'+str(folder),
            str(ROOT/'src/tests/native/WfpCallbackTests.c'),'-o',str(callback_exe)],
            capture_output=True,timeout=180,creationflags=0x08000000,env=env)
        if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace'))
        for mode in range(13):
            result=subprocess.run([str(callback_exe),str(mode)],capture_output=True,timeout=15,creationflags=0x08000000)
            expected_failure=version=='original' and mode in (0,4,5,6,7,8,9,10,11,12)
            if expected_failure:
                if result.returncode!=1 or b'check failed' not in result.stderr:
                    raise RuntimeError('Upstream callback control did not fail: '+str(mode))
            elif result.returncode:raise RuntimeError('Callback '+str(mode)+': '+result.stderr.decode())
        signature='NTSTATUS WFP_RegisterCallout(const GUID* calloutKey, const GUID* applicableLayer, UINT32* callout_id, UINT64* filter_id'
        signature+=', BOOLEAN* owned)\n{' if version=='prepared' else ')\n{'
        (folder/'WfpRegisterUnderTest.inc').write_text(function(data.decode(),signature),encoding='utf-8')
        register_exe=folder/'WfpRegisterTests.exe'
        built=subprocess.run([str(compiler),'cc','-std=c11',*definitions,'-I'+str(folder),
            str(ROOT/'src/tests/native/WfpRegisterTests.c'),'-o',str(register_exe)],
            capture_output=True,timeout=180,creationflags=0x08000000,env=env)
        if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace'))
        for mode in range(5):
            result=subprocess.run([str(register_exe),str(mode)],capture_output=True,timeout=15,creationflags=0x08000000)
            if version=='original' and mode!=1:
                if result.returncode!=1 or b'check failed' not in result.stderr:
                    raise RuntimeError('Upstream registration control did not fail: '+str(mode))
            elif result.returncode:raise RuntimeError('Registration '+str(mode)+': '+result.stderr.decode())
    results.update(callback_cases=13,callback_upstream_negative_controls=10)
    results.update(registration_cases=5,registration_upstream_negative_controls=4)
    results.update(upstream_negative_controls=len(MODES),installed=False,
                   limits='Extracted function, kernel/BFE modeled; live lifecycle and reload policy atomicity remain unaccepted')
    (prepared/'test-result.json').write_text(json.dumps(results,indent=2))
    print(json.dumps(results))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared-root',type=Path,required=True)
    parser.add_argument('--compiler',type=Path,default=ROOT/'work/toolchains/zig-pypi-0.13.0/ziglang/zig.exe')
    args=parser.parse_args();verify(args.prepared_root.resolve(),args.compiler.resolve())
