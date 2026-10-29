"""Extract request lifecycle transitions; never invoke installed services."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
from verify_queue_event_ownership import fragments
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def block(text,start):
    end=text.index('{',start)+1;depth=1
    while depth:
        if text[end]=='{':depth+=1
        elif text[end]=='}':depth-=1
        end+=1
    return text[start:end]
def extract(text):
    start=text.index('MSG_HEADER *QueueServer::GetRplHandler(')
    pending=block(text,text.index('    if ((! RequestObj->rpl_data_len)',start))
    start=text.index('MSG_HEADER *QueueServer::PutRplHandler(')
    end=text.index('// PutReqHandler',start)
    part=text[start:end];marker='    if (! RequestObj->client_pid)'
    abandoned=block(part,part.index(marker)) if marker in part else ''
    notify=block(text,text.index('void QueueServer::NotifyHandler('))
    return {'QueuePendingUnderTest.inc':pending,'QueueAbandonedUnderTest.inc':abandoned,
            'QueueNotifyUnderTest.inc':notify,'QueueDeleteUnderTest.inc':fragments(text)[1]}
def run(source,folder,compiler):
    folder.mkdir(parents=True)
    for name,text in extract(source.read_text(encoding='utf-8')).items():
        (folder/name).write_text(text,encoding='utf-8')
    exe=folder/'QueueRequestLifecycleTests.exe'
    fixture=ROOT/'src/tests/native/QueueRequestLifecycleTests.cpp'
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(folder/'zig-cache'))
    build=subprocess.run([str(compiler),'c++','-std=c++17','-I'+str(folder),str(fixture),'-o',str(exe)],capture_output=True,timeout=180,env=env,creationflags=0x08000000)
    if build.returncode:raise RuntimeError(build.stderr.decode(errors='replace'))
    result=subprocess.run([str(exe)],capture_output=True,timeout=15,creationflags=0x08000000)
    (folder/'run.json').write_text(json.dumps(dict(returncode=result.returncode,stdout=result.stdout.decode(),stderr=result.stderr.decode(),source_sha256=sha(source),test_sha256=sha(fixture)),indent=2),encoding='utf-8')
    return result

def main(prepared,output,compiler):
    if output.exists():raise RuntimeError('Preserve lifecycle evidence')
    source=prepared/'prepared/Sandboxie/core/svc/queueserver.cpp'
    metadata=json.loads((prepared/'manifest.json').read_text())['files']['queueserver.cpp']
    if sha(source)!=metadata['prepared_sha256']:raise RuntimeError('Queue source differs')
    result=run(source,output/'prepared',compiler)
    if result.returncode:raise RuntimeError('Prepared queue lifecycle check failed')
    checks=json.loads(result.stdout)
    if checks.get('cases')!=10 or checks.get('passed') is not True:raise RuntimeError('Incomplete lifecycle cases')
    original=run(prepared/'original/Sandboxie/core/svc/queueserver.cpp',output/'original',compiler)
    if original.returncode!=3:raise RuntimeError('Upstream lifecycle negative control did not fail')
    checks.update(original_negative_controls=1,prepared_source_sha256=sha(source),test_sha256=sha(ROOT/'src/tests/native/QueueRequestLifecycleTests.cpp'))
    (output/'result.json').write_text(json.dumps(checks,indent=2),encoding='utf-8');print(json.dumps(checks))
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('prepared-root','output','compiler'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();main(a.prepared_root,a.output,a.compiler)
