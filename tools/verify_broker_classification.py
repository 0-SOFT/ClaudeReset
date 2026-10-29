"""Execute the prepared broker classifier bodies with deterministic API stubs."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main(combined,output,compiler):
    if output.exists():raise RuntimeError('Preserve previous classifier evidence')
    manifest=json.loads((combined/'source-manifest.json').read_text())
    names=['Sandboxie/core/svc/CrBrokerWindows.h','Sandboxie/core/drv/CrBrokerQuery.h','Sandboxie/core/drv/process_api.c']
    paths=[combined/'source'/n for n in names]
    for n,p in zip(names,paths):
        if sha(p)!=manifest[n]:raise RuntimeError('Classifier source differs: '+n)
    source=paths[0].read_text();start=source.index('static bool CrIsStrictSandbox(')
    fragment=source[start:source.index('\n#endif',start)]
    driver=paths[2].read_text()
    query=driver[driver.index('_FX NTSTATUS Process_Api_QueryInfo('):]
    if (query.count('return CrBrokerQuery(proc, args->process_id.val, args->info_data.val);')!=1
            or query.index('return CrBrokerQuery(')>query.index('ProcessId = args->process_id.val;')):
        raise RuntimeError('Driver dispatch is not wired before legacy lookup')
    output.mkdir(parents=True)
    (output/'BrokerClassifierUnderTest.inc').write_text(fragment,encoding='utf-8')
    exe=output/'BrokerClassificationTests.exe'
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(ROOT/'work/toolchains/zig-cache'))
    build=subprocess.run([str(compiler),'c++','-std=c++17','-include','initializer_list',
        '-I'+str(output),'-I'+str(paths[1].parent),str(ROOT/'src/tests/native/BrokerClassificationTests.cpp'),
        '-o',str(exe)],capture_output=True,timeout=180,env=env,creationflags=0x08000000)
    if build.returncode:raise RuntimeError(build.stderr.decode(errors='replace'))
    run=subprocess.run([str(exe)],capture_output=True,timeout=15,creationflags=0x08000000)
    if run.returncode:raise RuntimeError(run.stderr.decode(errors='replace'))
    result=json.loads(run.stdout)
    # Both dangerous regressions must actually fail the same native assertions.
    negative=0
    for label,service,driver_header in (
        ('unknown-allowed',fragment.replace('if (!process) return true;','if (!process) return false;'),paths[1].read_text()),
        ('exit-allowed',fragment,paths[1].read_text().replace(' || PsGetProcessExitProcessCalled(processObject)','')),
        ('terminated-allowed',fragment,paths[1].read_text().replace('(target || PsGetProcessExitProcessCalled(processObject))',
            '((target && !target->terminated) || PsGetProcessExitProcessCalled(processObject))'))):
        mutant=output/label;mutant.mkdir()
        (mutant/'BrokerClassifierUnderTest.inc').write_text(service,encoding='utf-8')
        (mutant/'CrBrokerQuery.h').write_text(driver_header,encoding='utf-8')
        binary=mutant/'BrokerClassificationTests.exe'
        compile_mutant=subprocess.run([str(compiler),'c++','-std=c++17','-include','initializer_list',
            '-I'+str(mutant),str(ROOT/'src/tests/native/BrokerClassificationTests.cpp'),'-o',str(binary)],
            capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if compile_mutant.returncode:raise RuntimeError('Negative control did not compile')
        rejected=subprocess.run([str(binary)],capture_output=True,timeout=15,creationflags=0x08000000)
        if rejected.returncode!=3:raise RuntimeError('Classifier negative control was not rejected')
        negative+=1
    result['negative_controls']=negative
    result['source_sha256']={n:sha(p) for n,p in zip(names,paths)}
    result['test_sha256']=sha(ROOT/'src/tests/native/BrokerClassificationTests.cpp')
    result['loaded_driver_verified']=False
    (output/'result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--combined',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--compiler',type=Path,required=True);a=p.parse_args();main(a.combined,a.output,a.compiler)
