"""Verify exact prepared queue event ownership, including old failure control."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def fragments(source):
    start=source.index('MSG_HEADER *QueueServer::PutReqHandler(')
    tail=source[source.index('    RequestObj->client_pid =',start):source.index('// GetRplHandler',start)]
    tail=tail[:tail.rindex('}')+1]
    start=source.index('void QueueServer::DeleteRequestObj(')
    end=source.index('// StartupHandler',start)
    delete=source[start:end];delete=delete[:delete.rindex('}')+1]
    return tail,delete

def main(prepared,output,compiler):
    if output.exists():raise RuntimeError('Preserve queue ownership evidence')
    metadata=json.loads((prepared/'manifest.json').read_text())['files']['queueserver.cpp']
    source=prepared/'prepared/Sandboxie/core/svc/queueserver.cpp'
    if sha(source)!=metadata['prepared_sha256']:raise RuntimeError('Queue source differs from preparation')
    output.mkdir(parents=True);results={}
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(output/'zig-cache'))
    fixture=ROOT/'src/tests/native/QueueEventOwnershipTests.cpp'
    for label in ('prepared','original'):
        folder=output/label;folder.mkdir()
        text=(prepared/label/'Sandboxie/core/svc/queueserver.cpp').read_text(encoding='utf-8')
        tail,delete=fragments(text)
        (folder/'QueueEventTailUnderTest.inc').write_text(tail,encoding='utf-8')
        (folder/'QueueDeleteUnderTest.inc').write_text(delete,encoding='utf-8')
        exe=folder/'QueueEventOwnershipTests.exe'
        build=subprocess.run([str(compiler),'c++','-std=c++17','-include','initializer_list','-I'+str(folder),str(fixture),'-o',str(exe)],
            capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if build.returncode:raise RuntimeError(build.stderr.decode(errors='replace'))
        run=subprocess.run([str(exe)],capture_output=True,timeout=15,creationflags=0x08000000)
        if run.returncode!=(0 if label=='prepared' else 3):raise RuntimeError('Unexpected queue ownership control result')
        results[label]=run.returncode
        if label=='prepared':checks=json.loads(run.stdout)
        ids=subprocess.run([str(exe),'--request-id'],capture_output=True,timeout=15,creationflags=0x08000000)
        if ids.returncode!=(0 if label=='prepared' else 3):raise RuntimeError('Unexpected queue request ID control result')
        if label=='prepared':
            id_checks=json.loads(ids.stdout)
            if id_checks.get('request_id_boundary_checks')!=4 or id_checks.get('passed') is not True:
                raise RuntimeError('Incomplete queue request ID boundary checks')
        collision=subprocess.run([str(exe),'--collision'],capture_output=True,timeout=15,creationflags=0x08000000)
        if collision.returncode!=(0 if label=='prepared' else 3):raise RuntimeError('Unexpected live queue ID collision control result')
        if label=='prepared':
            collision_checks=json.loads(collision.stdout)
            if collision_checks.get('request_id_collision_checks')!=6 or collision_checks.get('passed') is not True:
                raise RuntimeError('Incomplete live queue ID collision checks')
        lifetime=subprocess.run([str(exe),'--process-lifetime'],capture_output=True,timeout=15,creationflags=0x08000000)
        if lifetime.returncode!=(0 if label=='prepared' else 3):raise RuntimeError('Unexpected client process lifetime control result')
        if label=='prepared':
            lifetime_checks=json.loads(lifetime.stdout)
            if lifetime_checks.get('process_lifetime_checks')!=4 or lifetime_checks.get('passed') is not True:
                raise RuntimeError('Incomplete client process lifetime checks')
    checks.update(original_negative_controls=4,request_id_boundary_checks=4,request_id_collision_checks=6,process_lifetime_checks=4,
                  prepared_source_sha256=sha(source),test_sha256=sha(fixture),
                  real_allocation_failure_injected=False,api_stubs=True)
    (output/'result.json').write_text(json.dumps(checks,indent=2),encoding='utf-8');print(json.dumps(checks))
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('prepared-root','output','compiler'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();main(a.prepared_root,a.output,a.compiler)
