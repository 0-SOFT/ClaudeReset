"""Test exact queue reply publication and an original-source negative control."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main(prepared,output,compiler):
    if output.exists():raise RuntimeError('Preserve queue reply evidence')
    metadata=json.loads((prepared/'manifest.json').read_text())['files']['queueserver.cpp']
    source=prepared/'prepared/Sandboxie/core/svc/queueserver.cpp'
    if sha(source)!=metadata['prepared_sha256']:raise RuntimeError('Queue source differs from preparation')
    output.mkdir(parents=True)
    fixture=ROOT/'src/tests/native/QueueReplyOwnershipTests.cpp'
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(output/'zig-cache'))
    for label in ('prepared','original'):
        folder=output/label;folder.mkdir()
        text=(prepared/label/'Sandboxie/core/svc/queueserver.cpp').read_text(encoding='utf-8')
        start=text.index('MSG_HEADER *QueueServer::PutRplHandler(')
        start=text.index('    if (RequestObj->req_data_len',start)
        fragment=text[start:text.index('\nfinish:',start)]
        (folder/'QueueReplyUnderTest.inc').write_text(fragment,encoding='utf-8')
        exe=folder/'QueueReplyOwnershipTests.exe'
        build=subprocess.run([str(compiler),'c++','-std=c++17','-I'+str(folder),str(fixture),'-o',str(exe)],
            capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if build.returncode:raise RuntimeError(build.stderr.decode(errors='replace'))
        run=subprocess.run([str(exe)],capture_output=True,timeout=15,creationflags=0x08000000)
        if run.returncode!=(0 if label=='prepared' else 3):raise RuntimeError('Unexpected queue reply control result')
        if label=='prepared':checks=json.loads(run.stdout)
    if checks.get('cases')!=6 or checks.get('passed') is not True:raise RuntimeError('Incomplete queue reply checks')
    checks.update(original_negative_controls=1,prepared_source_sha256=sha(source),test_sha256=sha(fixture))
    (output/'result.json').write_text(json.dumps(checks,indent=2),encoding='utf-8');print(json.dumps(checks))
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('prepared-root','output','compiler'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();main(args.prepared_root,args.output,args.compiler)
