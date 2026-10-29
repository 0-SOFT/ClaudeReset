"""Collect a known open reload-atomicity defect; this is not an acceptance test."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from prepare_managed_config import function

ROOT=Path(__file__).resolve().parents[1]


def main(prepared,compiler,output):
    prepared=prepared.resolve();output=output.resolve()
    if output.exists():raise RuntimeError('Choose a fresh diagnostic directory')
    manifest=json.loads((prepared/'manifest.json').read_text(encoding='utf-8'))
    name=next(name for name in manifest['files'] if name.endswith('/conf.c'))
    data=(prepared/'prepared'/name).read_bytes()
    digest=hashlib.sha256(data).hexdigest()
    if digest!=manifest['files'][name]['prepared_sha256']:raise RuntimeError('Prepared source differs')
    flags=(prepared/'ManagedApiFlags.h').read_bytes()
    if hashlib.sha256(flags).hexdigest()!=manifest['api_flags_sha256']:raise RuntimeError('Flags differ')
    source=data.decode('utf-8');read=function(source,'_FX NTSTATUS Conf_Read(ULONG session_id, BOOLEAN require_ready)')
    start=read.index('        BOOLEAN done = FALSE;')
    end=read.index('    Mem_Free(path, path_len);',start)
    publication='static NTSTATUS Publish(CONF_DATA data, BOOLEAN require_ready) {\n'
    publication+='NTSTATUS status=STATUS_SUCCESS; POOL *pool=data.pool;\nif(NT_SUCCESS(status)){\n'
    publication+=read[start:end]+'if(pool)Pool_Delete(pool);return status;\n}\n'
    output.mkdir(parents=True)
    (output/'ManagedPublicationUnderTest.inc').write_text(publication,encoding='utf-8')
    (output/'ManagedReloadUnderTest.inc').write_text(function(source,'_FX NTSTATUS Conf_Api_Reload(PROCESS *proc, ULONG64 *parms)'),encoding='utf-8')
    (output/'ManagedApiFlags.h').write_bytes(flags)
    fixture=ROOT/'src/tests/native/ManagedReloadAtomicityProbe.c';exe=output/'reload-atomicity-probe.exe'
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(output/'zig-cache'))
    built=subprocess.run([str(compiler),'cc','-x','c','-std=c11','-I'+str(output),str(fixture),'-o',str(exe)],
                         capture_output=True,timeout=180,env=env,creationflags=0x08000000)
    if built.returncode:raise RuntimeError(built.stderr.decode(errors='replace')[-5000:])
    rows={}
    for mode in ('ready','before-publication','wfp-after-publication','plain-after-publication'):
        run=subprocess.run([str(exe),mode],capture_output=True,timeout=15,creationflags=0x08000000)
        row=json.loads(run.stdout);row['exit_code']=run.returncode;rows[mode]=row
        expected=3 if mode.endswith('after-publication') else 0
        if run.returncode!=expected:raise RuntimeError('Diagnostic changed; review '+mode)
    assert rows['ready']['status']==0 and rows['ready']['generation']==2 and rows['ready']['notices']==1
    assert rows['before-publication']['status']==-7 and rows['before-publication']['reads']==0
    for mode in ('wfp-after-publication','plain-after-publication'):
        assert rows[mode]['generation']==2 and rows[mode]['old_pool_freed']==1 and rows[mode]['notices']==0
    result=dict(kind='known_open_defect_diagnostic',source_sha256=digest,
                fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),cases=rows,
                kernel_operations_modeled=True,parser_modeled=True,loaded_driver_test=False,
                atomicity_requirement_satisfied=False,release_ready=False)
    (output/'result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('prepared','compiler','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();main(args.prepared,args.compiler,args.output)
