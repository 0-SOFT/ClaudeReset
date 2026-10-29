"""Test extracted registration cleanup; model scheduling, never load a driver."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from prepare_managed_config import function

ROOT=Path(__file__).resolve().parents[1]
CASES=('replacement','already-cleared','stale-empty-port','own','own-empty-port','null-identity')


def verify(prepared,compiler,output):
    if output.exists():raise RuntimeError('Preserve previous lifecycle evidence')
    manifest=json.loads((prepared/'manifest.json').read_text())
    sources={}
    for label in ('prepared','original'):
        path=prepared/label/'Sandboxie/core/drv/api.c'
        raw=path.read_bytes()
        key='prepared_sha256' if label=='prepared' else 'original_normalized_sha256'
        if hashlib.sha256(raw).hexdigest()!=manifest['files']['Sandboxie/core/drv/api.c'][key]:
            raise RuntimeError('Registration source differs from manifest')
        sources[label]=raw.decode('utf-8')
    output.mkdir(parents=True);rows=[]
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(ROOT/'work/toolchains/zig-cache'))
    for label,source in sources.items():
        folder=output/label;folder.mkdir()
        signature='_FX void Api_ResetServiceProcess('+('HANDLE ProcessId' if label=='prepared' else 'void')+')'
        (folder/'ManagedServiceResetUnderTest.inc').write_text(function(source,signature),encoding='utf-8')
        exe=folder/'ManagedServiceResetTests.exe'
        command=[str(compiler),'c++','-std=c++17','-I'+str(folder),
                 str(ROOT/'src/tests/native/ManagedServiceResetTests.cpp'),'-o',str(exe)]
        if label=='prepared':command.append('-DCR_RESET_HAS_PID=1')
        built=subprocess.run(command,capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace')[-4000:])
        for case in CASES:
            tested=subprocess.run([str(exe),case],capture_output=True,timeout=15,creationflags=0x08000000)
            expected=0 if label=='prepared' or case=='own-empty-port' else 1
            if tested.returncode!=expected or expected and b'check failed' not in tested.stderr:
                raise RuntimeError('Unexpected service-reset outcome: '+label+'/'+case)
            rows.append(dict(source=label,case=case,exit_code=tested.returncode,
                             positive=label=='prepared',negative_control=expected==1))
    result=dict(schema=1,cases=rows,passed=True,installed=False,kernel_test=False,
                prepared_source_sha256=manifest['files']['Sandboxie/core/drv/api.c']['prepared_sha256'],
                test_source_sha256=hashlib.sha256((ROOT/'src/tests/native/ManagedServiceResetTests.cpp').read_bytes()).hexdigest(),
                limits=['Deterministic user-mode stubs; no kernel scheduling or installed-client acceptance.'])
    (output/'result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('prepared-root','compiler','output-root'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();verify(args.prepared_root.resolve(),args.compiler.resolve(),args.output_root.resolve())
